"""会话生命周期测试。

覆盖：
- 刷新令牌一次性轮换，旧令牌重放撤销整族且原因 refresh_replay；
- 同一刷新令牌并发刷新：恰一个成功，其余明确失败，且不存在两份同时生效凭据；
- 登出 / 管理员主动撤销 / 密钥轮换后访问令牌立即失效；
- 过期令牌以 token_expired 区分拒绝。
"""

from __future__ import annotations

import logging
import threading

import pytest

from auth.errors import AuthError, DenyReason
from auth.keys import KeyManager
from auth.service import AuthService
from auth.store import LocalStore

log = logging.getLogger("test.session")


class FakeClock:
    def __init__(self, t: int = 1_000_000) -> None:
        self.t = t

    def __call__(self) -> float:
        return float(self.t)

    def advance(self, seconds: int) -> None:
        self.t += seconds


def build_service(access_ttl: int = 900, refresh_ttl: int = 3600) -> tuple[AuthService, FakeClock]:
    clock = FakeClock()
    svc = AuthService(LocalStore(), KeyManager(),
                      access_ttl=access_ttl, refresh_ttl=refresh_ttl,
                      clock=clock)
    svc.add_role_permission("user", "doc:read")
    svc.create_user("alice", "pw", ["user"])
    return svc, clock


def auth_header(tokens) -> str:
    return "Bearer " + tokens.access_token


def test_refresh_rotates_and_old_refresh_is_replay() -> None:
    svc, _ = build_service()
    first = svc.login("alice", "pw")
    log.info("输入: family=%s 使用初始 refresh 刷新", first.family_id[:8])

    second = svc.refresh(first.refresh_token)
    assert second.refresh_token != first.refresh_token
    log.info("判定依据: 新 refresh 已换发，旧 refresh 标记 used=True")

    # 第二次提交旧刷新令牌 -> 重放，整族撤销
    with pytest.raises(AuthError) as exc:
        svc.refresh(first.refresh_token)
    log.info("输入: 重放旧 refresh；判定: reason=%s 动作=撤销整族",
             exc.value.reason.value)
    assert exc.value.reason == DenyReason.REFRESH_REPLAY

    # 换发后的新令牌同样失效：不存在两份同时生效的凭据
    with pytest.raises(AuthError) as exc2:
        svc.refresh(second.refresh_token)
    assert exc2.value.reason in (DenyReason.REFRESH_REPLAY, DenyReason.FAMILY_REVOKED)
    for tokens in (first, second):
        with pytest.raises(AuthError) as exc3:
            svc.authenticate(auth_header(tokens))
        assert exc3.value.reason in (
            DenyReason.ACCESS_TOKEN_REVOKED, DenyReason.FAMILY_REVOKED)
    log.info("判定依据: 重放后族内全部访问/刷新凭据立即失效")


def test_concurrent_refresh_only_one_succeeds() -> None:
    svc, _ = build_service()
    tokens = svc.login("alice", "pw")
    results: list[object] = []
    barrier = threading.Barrier(32)

    def worker() -> None:
        barrier.wait()  # 尽量让所有线程同时进入
        try:
            results.append(("ok", svc.refresh(tokens.refresh_token)))
        except AuthError as e:
            results.append(("err", e.reason))

    threads = [threading.Thread(target=worker) for _ in range(32)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "err"]
    log.info("输入: 32 线程并发提交同一 refresh；成功=%d 失败=%d",
             len(successes), len(failures))
    assert len(successes) == 1, f"应恰好一个成功，实际 {len(successes)}"
    assert len(failures) == 31
    # 落败者必须得到明确原因（重放；首个落败者触发整族撤销，之后可能看到族撤销）
    assert all(r[1] in (DenyReason.REFRESH_REPLAY, DenyReason.FAMILY_REVOKED)
               for r in failures)
    log.info("判定依据: 刷新临界区为 store 单锁原子操作，落败者原因可区分")

    # 唯一“成功”的返回凭据也因族已撤销而不可用 -> 不存在两份同时生效凭据
    winner_tokens = successes[0][1]
    with pytest.raises(AuthError) as exc:
        svc.authenticate(auth_header(winner_tokens))
    assert exc.value.reason in (
        DenyReason.ACCESS_TOKEN_REVOKED, DenyReason.FAMILY_REVOKED)
    with pytest.raises(AuthError):
        svc.refresh(winner_tokens.refresh_token)
    log.info("判定依据: 竞争落败者的重放判定撤销整族，赢家的新凭据同样失效")


def test_unknown_and_malformed_credentials_are_distinct() -> None:
    svc, _ = build_service()
    with pytest.raises(AuthError) as e1:
        svc.refresh("not-a-real-token")
    assert e1.value.reason == DenyReason.REFRESH_UNKNOWN
    with pytest.raises(AuthError) as e2:
        svc.authenticate(None)
    assert e2.value.reason == DenyReason.MISSING_CREDENTIAL
    with pytest.raises(AuthError) as e3:
        svc.authenticate("Bearer not-a-jwt")
    assert e3.value.reason == DenyReason.MALFORMED_TOKEN
    log.info("输入: 未知 refresh / 缺失凭据 / 畸形令牌；判定: 三者原因互不相同")


def test_logout_revokes_access_token_immediately() -> None:
    svc, _ = build_service()
    tokens = svc.login("alice", "pw")
    header = auth_header(tokens)
    svc.authenticate(header)  # 登出前可用
    svc.logout(tokens.access_token)
    log.info("输入: 登出后立即重放同一 access token（仍在原始有效期内）")
    with pytest.raises(AuthError) as exc:
        svc.authenticate(header)
    assert exc.value.reason in (
        DenyReason.ACCESS_TOKEN_REVOKED, DenyReason.FAMILY_REVOKED)
    log.info("判定: reason=%s —— jti 已在存活集合中摘除/族已撤销", exc.value.reason.value)
    with pytest.raises(AuthError):
        svc.refresh(tokens.refresh_token)


def test_admin_family_revocation_takes_effect_immediately() -> None:
    svc, _ = build_service()
    tokens = svc.login("alice", "pw")
    svc.revoke_family(tokens.family_id)
    log.info("输入: 管理员撤销 family=%s", tokens.family_id[:8])
    with pytest.raises(AuthError) as exc:
        svc.authenticate(auth_header(tokens))
    assert exc.value.reason in (
        DenyReason.FAMILY_REVOKED, DenyReason.ACCESS_TOKEN_REVOKED)
    with pytest.raises(AuthError) as exc2:
        svc.refresh(tokens.refresh_token)
    assert exc2.value.reason in (DenyReason.FAMILY_REVOKED, DenyReason.REFRESH_REPLAY)


def test_key_rotation_invalidates_existing_access_tokens() -> None:
    svc, _ = build_service()
    tokens = svc.login("alice", "pw")
    svc.rotate_keys()
    log.info("输入: 密钥轮换后提交旧 access token（未过期、jti 仍活跃）")
    with pytest.raises(AuthError) as exc:
        svc.authenticate(auth_header(tokens))
    assert exc.value.reason == DenyReason.KEY_NOT_ACTIVE
    log.info("判定: reason=key_not_active —— kid 不在当前活动密钥中")


def test_expired_access_token_is_distinct_reason() -> None:
    svc, clock = build_service(access_ttl=10)
    tokens = svc.login("alice", "pw")
    clock.advance(11)
    log.info("输入: 时钟推进超过 access_ttl")
    with pytest.raises(AuthError) as exc:
        svc.authenticate(auth_header(tokens))
    assert exc.value.reason == DenyReason.TOKEN_EXPIRED
    log.info("判定: reason=token_expired")


def test_refresh_after_expiry_rejects_and_revokes_family() -> None:
    svc, clock = build_service(refresh_ttl=60)
    tokens = svc.login("alice", "pw")
    clock.advance(61)
    with pytest.raises(AuthError) as exc:
        svc.refresh(tokens.refresh_token)
    assert exc.value.reason == DenyReason.TOKEN_EXPIRED
    log.info("输入: 过期 refresh；判定: token_expired 且族被撤销")
    with pytest.raises(AuthError):
        svc.authenticate(auth_header(tokens))


def test_bad_signature_distinct_from_revocation() -> None:
    svc, _ = build_service()
    tokens = svc.login("alice", "pw")
    head, payload, sig = tokens.access_token.split(".")
    forged = f"{head}.{payload}.{'A' if sig[0] != 'A' else 'B' + sig[1:]}"
    with pytest.raises(AuthError) as exc:
        svc.authenticate("Bearer " + forged)
    assert exc.value.reason == DenyReason.BAD_SIGNATURE
    log.info("输入: 伪造签名；判定: bad_signature，与撤销/过期原因可区分")

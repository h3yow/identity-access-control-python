"""身份认证与会话访问控制测试。

覆盖：并发刷新、刷新令牌重放、撤销后继续使用、权限调整立即生效、越权访问。
每个用例打印输入与判定依据，断言结果稳定、失败原因可区分。
"""

from __future__ import annotations

import logging
import threading

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.authz import Permission
from app.errors import AuthError, DenyReason
from app.service import AuthService

log = logging.getLogger("test.auth")


class Clock:
    """可控时钟，用于过期场景。"""

    def __init__(self, t: int = 1_000_000) -> None:
        self.t = t

    def __call__(self) -> int:
        return self.t

    def advance(self, seconds: int) -> None:
        self.t += seconds


@pytest.fixture()
def clock() -> Clock:
    return Clock()


@pytest.fixture()
def svc(clock: Clock) -> AuthService:
    service = AuthService(access_ttl=300, refresh_ttl=3600, now=clock)
    service.roles.set_role_permissions("reader", {Permission("document", "read")})
    service.roles.set_role_permissions("writer", {Permission("document", "write")})
    return service


def outcome(fn, *args, **kwargs) -> str:
    """执行操作并返回可区分的判定结果字符串，同时打印判定依据。"""
    try:
        fn(*args, **kwargs)
        result = "allow"
    except AuthError as exc:
        result = exc.reason.value
    log.info("判定结果 -> %s", result)
    return result


# ---------------------------------------------------------------- 并发刷新

def test_concurrent_refresh_only_one_succeeds(svc: AuthService) -> None:
    pair = svc.login("alice", ["reader"])
    log.info("输入: 同一刷新令牌并发提交 32 次, session=%s", pair.session_id)

    results: list[tuple[str, object]] = []
    barrier = threading.Barrier(32)

    def worker() -> None:
        barrier.wait()
        try:
            new_pair = svc.refresh(pair.refresh_token)
            results.append(("ok", new_pair))
        except AuthError as exc:
            results.append((exc.reason.value, None))

    threads = [threading.Thread(target=worker) for _ in range(32)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    oks = [r for r in results if r[0] == "ok"]
    log.info("判定依据: 成功=%d, 拒绝原因分布=%s",
             len(oks), sorted({r[0] for r in results if r[0] != "ok"}))
    assert len(oks) == 1, "并发刷新只允许一个成功"
    assert all(r[0] == DenyReason.REFRESH_REUSED.value for r in results if r[0] != "ok")

    # 并发双提交与重放攻击不可区分，按重放处理：会话族已撤销，
    # 因此不存在两份同时生效的有效凭据（胜者的凭据也随族失效）。
    winner = oks[0][1]
    log.info("判定依据: 检查胜者凭据随会话族一并失效")
    assert outcome(svc.authorize, winner.access_token,
                   Permission("document", "read")) == DenyReason.REFRESH_REUSED.value


def test_concurrent_refresh_result_is_stable(svc: AuthService) -> None:
    """并发刷新结束后，所有输家重试仍得到同样的拒绝原因（结果可解释、稳定）。"""
    pair = svc.login("alice", ["reader"])
    try:
        svc.refresh(pair.refresh_token)
    except AuthError:
        pytest.fail("首次刷新应成功")
    for _ in range(5):
        reason = outcome(svc.refresh, pair.refresh_token)
        assert reason == DenyReason.REFRESH_REUSED.value


# ---------------------------------------------------------------- 刷新令牌重放

def test_refresh_token_replay_revokes_family(svc: AuthService) -> None:
    pair = svc.login("alice", ["reader"])
    rotated = svc.refresh(pair.refresh_token)
    log.info("输入: 重放已轮换的刷新令牌, session=%s", pair.session_id)

    reason = outcome(svc.refresh, pair.refresh_token)
    assert reason == DenyReason.REFRESH_REUSED.value

    # 整个会话族失效：新访问令牌、新刷新令牌都不得放行
    log.info("判定依据: 重放后检查族内新凭据")
    assert outcome(svc.authorize, rotated.access_token,
                   Permission("document", "read")) == DenyReason.REFRESH_REUSED.value
    assert outcome(svc.refresh, rotated.refresh_token) == DenyReason.REFRESH_REUSED.value


def test_unknown_refresh_token_is_malformed_not_reused(svc: AuthService) -> None:
    """伪造令牌与重放原因可区分。"""
    log.info("输入: 结构非法的刷新令牌")
    assert outcome(svc.refresh, "not-a-token") == DenyReason.TOKEN_MALFORMED.value


# ---------------------------------------------------------------- 撤销后继续使用

def test_logout_invalidates_access_token_immediately(svc: AuthService) -> None:
    pair = svc.login("alice", ["reader"])
    assert svc.authorize(pair.access_token, Permission("document", "read")) == "alice"
    svc.logout(pair.access_token)
    log.info("输入: 登出后继续使用原访问令牌, session=%s", pair.session_id)
    assert outcome(svc.authorize, pair.access_token,
                   Permission("document", "read")) == DenyReason.TOKEN_REVOKED.value
    # 登出后刷新同样拒绝
    assert outcome(svc.refresh, pair.refresh_token) == DenyReason.TOKEN_REVOKED.value


def test_revoke_session_invalidates_all_tokens(svc: AuthService) -> None:
    pair = svc.login("alice", ["reader"])
    svc.revoke_session(pair.session_id)
    log.info("输入: 主动撤销后使用访问令牌与刷新令牌, session=%s", pair.session_id)
    assert outcome(svc.authorize, pair.access_token,
                   Permission("document", "read")) == DenyReason.TOKEN_REVOKED.value
    assert outcome(svc.refresh, pair.refresh_token) == DenyReason.TOKEN_REVOKED.value


def test_key_rotation_invalidates_tokens_within_original_ttl(svc: AuthService, clock: Clock) -> None:
    pair = svc.login("alice", ["reader"])
    svc.rotate_keys()
    log.info("输入: 密钥轮换后在原有效期内使用旧访问令牌/刷新令牌")
    assert clock.t < 1_000_000 + 300  # 仍在原有效期内
    assert outcome(svc.authorize, pair.access_token,
                   Permission("document", "read")) == DenyReason.TOKEN_REVOKED.value
    assert outcome(svc.refresh, pair.refresh_token) == DenyReason.TOKEN_REVOKED.value
    # 轮换后新登录不受影响
    fresh = svc.login("bob", ["reader"])
    assert svc.authorize(fresh.access_token, Permission("document", "read")) == "bob"


def test_expired_token_reason_is_distinguishable(svc: AuthService, clock: Clock) -> None:
    pair = svc.login("alice", ["reader"])
    clock.advance(301)
    log.info("输入: 过期访问令牌")
    assert outcome(svc.authorize, pair.access_token,
                   Permission("document", "read")) == DenyReason.TOKEN_EXPIRED.value


# ---------------------------------------------------------------- 权限调整立即生效

def test_permission_change_takes_effect_on_next_request(svc: AuthService) -> None:
    pair = svc.login("alice", ["reader"])
    write = Permission("document", "write")
    log.info("输入: reader 角色执行 document:write（未授权）")
    assert outcome(svc.authorize, pair.access_token, write) == DenyReason.FORBIDDEN.value

    # 调整角色权限，下一次请求即生效（不重新登录）
    svc.roles.set_role_permissions("reader", {Permission("document", "read"), write})
    log.info("判定依据: 角色权限已调整，原访问令牌再次判定")
    assert svc.authorize(pair.access_token, write) == "alice"

    # 收回权限同样立即生效
    svc.roles.set_role_permissions("reader", {Permission("document", "read")})
    assert outcome(svc.authorize, pair.access_token, write) == DenyReason.FORBIDDEN.value


# ---------------------------------------------------------------- 越权访问

def test_forbidden_does_not_leak_resource_existence(svc: AuthService) -> None:
    svc.authorizer.add_resource("doc-1", "document")
    pair = svc.login("alice", ["reader"])  # 只有 read，没有 write
    write = Permission("document", "write")
    log.info("输入: 无 write 权限，分别访问存在与不存在的资源")
    existing = outcome(svc.authorize, pair.access_token, write, "doc-1")
    missing = outcome(svc.authorize, pair.access_token, write, "ghost")
    assert existing == missing == DenyReason.FORBIDDEN.value, "越权时不得区分资源是否存在"


def test_authorized_but_missing_resource_is_not_found(svc: AuthService) -> None:
    svc.authorizer.add_resource("doc-1", "document")
    pair = svc.login("alice", ["reader"])
    log.info("输入: 有 read 权限，访问不存在的资源")
    assert outcome(svc.authorize, pair.access_token,
                   Permission("document", "read"), "ghost") == DenyReason.RESOURCE_NOT_FOUND.value


def test_malformed_token_reason_is_distinguishable(svc: AuthService) -> None:
    log.info("输入: 格式错误的访问令牌")
    assert outcome(svc.authorize, "garbage",
                   Permission("document", "read")) == DenyReason.TOKEN_MALFORMED.value


# ---------------------------------------------------------------- API 层一致性

def test_api_endpoints_return_distinguishable_errors(svc: AuthService) -> None:
    client = TestClient(create_app(svc))
    r = client.post("/login", json={"subject": "alice", "roles": ["reader"]})
    tokens = r.json()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    log.info("输入: HTTP 层登出后访问受保护资源, session=%s", tokens["session_id"])

    assert client.get("/resources/doc-1", headers=headers).status_code == 200
    assert client.post("/logout", headers=headers).status_code == 200
    r = client.get("/resources/doc-1", headers=headers)
    log.info("判定依据: HTTP %s body=%s", r.status_code, r.json())
    assert r.status_code == 401 and r.json()["error"] == "token_revoked"

    r = client.get("/resources/doc-1")
    assert r.status_code == 401 and r.json()["error"] == "token_malformed"

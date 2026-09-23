"""RBAC 授权判定测试。

覆盖：
- 权限细化到“资源:操作”，精确/通配匹配；
- 角色权限调整在下一次请求即生效（无缓存）；
- 越权 forbidden_operation 与凭据失效/格式错误原因可区分；
- 禁用账户立即拒绝。
"""

from __future__ import annotations

import logging

import pytest

from auth.errors import AuthError, DenyReason
from auth.keys import KeyManager
from auth.policy import permission_matches
from auth.service import AuthService
from auth.store import LocalStore

log = logging.getLogger("test.rbac")


def build_service() -> AuthService:
    svc = AuthService(LocalStore(), KeyManager())
    svc.add_role_permission("viewer", "doc:read")
    svc.add_role_permission("editor", "doc:read")
    svc.add_role_permission("editor", "doc:publish")
    svc.add_role_permission("admin", "*")
    svc.create_user("bob", "pw", ["viewer"])
    svc.create_user("alice", "pw", ["editor"])
    svc.create_user("root", "pw", ["admin"])
    return svc


@pytest.mark.parametrize(
    "granted,required,expected",
    [
        ("doc:read", "doc:read", True),
        ("doc:read", "doc:write", False),
        ("doc:*", "doc:publish", True),
        ("doc:*", "video:read", False),
        ("*", "anything:run", True),
    ],
)
def test_permission_matching(granted: str, required: str, expected: bool) -> None:
    log.info("输入: granted=%s required=%s 判定: %s", granted, required, expected)
    assert permission_matches(granted, required) is expected


def test_role_allows_and_denies_operations() -> None:
    svc = build_service()
    tokens = svc.login("bob", "pw")
    ctx = svc.authenticate("Bearer " + tokens.access_token)

    d_read = svc.authorize(ctx, "doc:read")
    log.info("输入: user=bob op=doc:read 判定依据=%s", d_read.explain())
    assert d_read.allowed and d_read.matched_permissions == ("doc:read",)

    d_pub = svc.authorize(ctx, "doc:publish")
    log.info("输入: user=bob op=doc:publish 判定依据=%s", d_pub.explain())
    assert not d_pub.allowed and d_pub.reason == DenyReason.FORBIDDEN_OPERATION.value

    with pytest.raises(AuthError) as exc:
        svc.guard("Bearer " + tokens.access_token, "doc:publish")
    assert exc.value.reason == DenyReason.FORBIDDEN_OPERATION


def test_permission_change_takes_effect_on_next_request() -> None:
    svc = build_service()
    tokens = svc.login("bob", "pw")

    def can_publish() -> bool:
        ctx = svc.authenticate("Bearer " + tokens.access_token)
        d = svc.authorize(ctx, "doc:publish")
        log.info("输入: 即时判定 op=doc:publish -> allowed=%s via=%s",
                 d.allowed, d.matched_permissions)
        return d.allowed

    assert can_publish() is False
    svc.add_role_permission("viewer", "doc:publish")
    assert can_publish() is True  # 下一次请求即生效，无需重新登录
    svc.remove_role_permission("viewer", "doc:publish")
    assert can_publish() is False


def test_wildcard_admin_role() -> None:
    svc = build_service()
    tokens = svc.login("root", "pw")
    ctx = svc.authenticate("Bearer " + tokens.access_token)
    for op in ("doc:read", "doc:delete", "admin:rotate_keys", "admin:revoke_session"):
        d = svc.authorize(ctx, op)
        log.info("输入: user=root op=%s 判定依据=%s", op, d.explain())
        assert d.allowed


def test_forbidden_distinct_from_missing_and_malformed() -> None:
    svc = build_service()
    tokens = svc.login("bob", "pw")
    # 凭据有效但越权 -> forbidden_operation
    with pytest.raises(AuthError) as e1:
        svc.guard("Bearer " + tokens.access_token, "doc:delete")
    # 无凭据 -> missing_credential
    with pytest.raises(AuthError) as e2:
        svc.guard(None, "doc:delete")
    # 凭据格式错误 -> malformed_token
    with pytest.raises(AuthError) as e3:
        svc.guard("Bearer garbage", "doc:delete")
    reasons = {e1.value.reason, e2.value.reason, e3.value.reason}
    log.info("输入: 越权/缺失/畸形；判定原因集合=%s", {r.value for r in reasons})
    assert reasons == {
        DenyReason.FORBIDDEN_OPERATION,
        DenyReason.MISSING_CREDENTIAL,
        DenyReason.MALFORMED_TOKEN,
    }


def test_disabled_user_denied_immediately() -> None:
    svc = build_service()
    tokens = svc.login("bob", "pw")
    header = "Bearer " + tokens.access_token
    svc.authenticate(header)
    svc.set_user_enabled("bob", False)
    log.info("输入: 用户被禁用后继续使用其未过期 access token")
    with pytest.raises(AuthError) as exc:
        svc.authenticate(header)
    assert exc.value.reason == DenyReason.USER_DISABLED

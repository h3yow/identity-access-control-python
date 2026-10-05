"""单会话撤销对当前会话的限制（回归：误撤销当前会话会把自己踢下线）。

覆盖业务：
- 撤销当前会话：明确、稳定、可区分地拒绝（409 current_session_revoke_denied），
  且拒绝后无任何副作用——当前访问令牌、整条刷新链路、名下其他会话、
  会话列表全部保持原状
- 撤销自己的其他会话：仍然生效，且不影响当前会话
- 失败边界：撤销他人会话 -> forbidden；撤销不存在的会话 -> session_not_found，
  不泄漏他人会话是否存在
"""

from __future__ import annotations

import logging
import threading

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.audit import AuditAction
from app.authz import Permission
from app.errors import AuthError, DenyReason
from app.service import AuthService

log = logging.getLogger("test.current_session_revoke")


class Clock:
    def __init__(self, t: int = 2_000_000) -> None:
        self.t = t
        self._lock = threading.Lock()

    def __call__(self) -> int:
        return self.t

    def advance(self, seconds: int) -> None:
        with self._lock:
            self.t += seconds


@pytest.fixture()
def clock() -> Clock:
    return Clock()


@pytest.fixture()
def svc(clock: Clock) -> AuthService:
    service = AuthService(
        access_ttl=300, refresh_ttl=3600,
        max_sessions_per_subject=5, audit_max_records=10_000, now=clock,
    )
    service.roles.set_role_permissions("reader", {Permission("document", "read")})
    return service


# ------------------------------------------------------------ 服务层：拒绝撤销当前会话

def test_revoke_current_session_is_distinctly_rejected(svc: AuthService) -> None:
    pair = svc.login("alice", ["reader"], device_label="current")
    with pytest.raises(AuthError) as ei:
        svc.revoke_owned_session("alice", pair.session_id, pair.session_id)
    log.info("撤销当前会话拒绝原因: %s", ei.value.reason.value)
    assert ei.value.reason is DenyReason.CURRENT_SESSION_REVOKE_DENIED


def test_rejected_revoke_leaves_no_side_effects(svc: AuthService) -> None:
    current = svc.login("alice", ["reader"], device_label="current")
    other = svc.login("alice", ["reader"], device_label="other")
    before = [i.session_id for i in svc.list_sessions("alice")]

    with pytest.raises(AuthError) as ei:
        svc.revoke_owned_session("alice", current.session_id, current.session_id)
    assert ei.value.reason is DenyReason.CURRENT_SESSION_REVOKE_DENIED

    # 当前访问令牌照旧可用
    assert svc.authorize(current.access_token,
                         Permission("document", "read")) == "alice"
    # 整条刷新链路照旧可用
    rotated = svc.refresh(current.refresh_token)
    assert rotated.session_id == current.session_id
    assert svc.authorize(rotated.access_token,
                         Permission("document", "read")) == "alice"
    # 其他会话不被连带失效
    assert svc.authorize(other.access_token,
                         Permission("document", "read")) == "alice"
    # 会话列表如实反映：两个会话都仍有效
    after = svc.list_sessions("alice")
    log.info("拒绝后会话列表: %s",
             [(i.session_id[:6], i.status.value) for i in after])
    assert [i.session_id for i in after] == before
    assert all(i.status.value == "active" for i in after)
    assert svc.sessions.active_count("alice") == 2


def test_rejected_revoke_is_audited(svc: AuthService) -> None:
    pair = svc.login("alice", ["reader"])
    with pytest.raises(AuthError):
        svc.revoke_owned_session("alice", pair.session_id, pair.session_id)
    records = svc.audit.query(
        subject="alice", actions={AuditAction.SESSION_REVOKE}, limit=100
    ).items
    log.info("撤销审计记录: %s", [(r.result, r.session_id[:6]) for r in records])
    assert len(records) == 1
    assert records[0].result == \
        f"denied:{DenyReason.CURRENT_SESSION_REVOKE_DENIED.value}"
    assert records[0].session_id == pair.session_id


# ------------------------------------------------------------ 撤销其他会话仍然生效

def test_revoke_other_own_session_still_works(svc: AuthService) -> None:
    current = svc.login("alice", ["reader"], device_label="current")
    other = svc.login("alice", ["reader"], device_label="other")

    info = svc.revoke_owned_session("alice", other.session_id, current.session_id)
    assert info.session_id == other.session_id
    assert info.status.value == "revoked"

    # 被撤销会话的访问令牌与刷新链路立即失效
    with pytest.raises(AuthError) as ei:
        svc.authorize(other.access_token, Permission("document", "read"))
    assert ei.value.reason is DenyReason.TOKEN_REVOKED
    with pytest.raises(AuthError) as ei:
        svc.refresh(other.refresh_token)
    assert ei.value.reason is DenyReason.TOKEN_REVOKED

    # 当前会话及其刷新链路不受影响
    assert svc.authorize(current.access_token,
                         Permission("document", "read")) == "alice"
    assert svc.refresh(current.refresh_token).session_id == current.session_id
    # 列表如实：只剩当前会话
    remaining = svc.list_sessions("alice")
    log.info("撤销其他会话后列表: %s",
             [(i.session_id[:6], i.status.value) for i in remaining])
    assert [i.session_id for i in remaining] == [current.session_id]


# ------------------------------------------------------------ 失败边界保持不变

def test_revoke_foreign_or_missing_session_unchanged(svc: AuthService) -> None:
    alice = svc.login("alice", ["reader"])
    bob = svc.login("bob", ["reader"])

    # 撤销他人会话 -> forbidden（且对方会话不受影响）
    with pytest.raises(AuthError) as ei:
        svc.revoke_owned_session("bob", alice.session_id, bob.session_id)
    log.info("撤销他人会话拒绝原因: %s", ei.value.reason.value)
    assert ei.value.reason is DenyReason.FORBIDDEN
    assert svc.authorize(alice.access_token,
                         Permission("document", "read")) == "alice"

    # 撤销不存在的会话 -> session_not_found
    with pytest.raises(AuthError) as ei:
        svc.revoke_owned_session("bob", "no-such-session", bob.session_id)
    log.info("撤销不存在会话拒绝原因: %s", ei.value.reason.value)
    assert ei.value.reason is DenyReason.SESSION_NOT_FOUND


# ------------------------------------------------------------ HTTP 层

def test_http_revoke_current_session_rejected_without_side_effects(
    svc: AuthService,
) -> None:
    client = TestClient(create_app(svc))

    def login(subject, label):
        r = client.post("/login", json={
            "subject": subject, "roles": ["reader"], "device_label": label,
        })
        assert r.status_code == 200, r.text
        return r.json()

    current = login("alice", "current")
    other = login("alice", "other")
    h = {"Authorization": f"Bearer {current['access_token']}"}

    # 撤销当前会话 -> 409，错误码可区分
    r = client.post(f"/sessions/{current['session_id']}/revoke", headers=h)
    log.info("撤销当前会话响应: %s %s", r.status_code, r.json())
    assert r.status_code == 409
    assert r.json()["error"] == "current_session_revoke_denied"

    # 当前访问令牌照旧可用（受保护资源 + 会话列表）
    assert client.get("/resources/doc-1", headers=h).status_code == 200
    sessions = client.get("/sessions", headers=h).json()["sessions"]
    assert {s["session_id"] for s in sessions} == \
        {current["session_id"], other["session_id"]}
    assert all(s["status"] == "active" for s in sessions)

    # 整条刷新链路照旧可用
    r = client.post("/refresh", json={"refresh_token": current["refresh_token"]})
    assert r.status_code == 200, r.text
    assert r.json()["session_id"] == current["session_id"]

    # 撤销自己的其他会话 -> 200，且不影响当前会话
    r = client.post(f"/sessions/{other['session_id']}/revoke", headers=h)
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    oh = {"Authorization": f"Bearer {other['access_token']}"}
    assert client.get("/resources/doc-1", headers=oh).status_code == 401
    assert client.get("/resources/doc-1", headers=h).status_code == 200

    # 撤销不存在的会话 -> 401 session_not_found
    r = client.post("/sessions/no-such-session/revoke", headers=h)
    assert r.status_code == 401
    assert r.json()["error"] == "session_not_found"

    # 撤销他人会话 -> 403 forbidden，不泄漏对方会话是否存在
    bob = login("bob", "bob-device")
    r = client.post(f"/sessions/{bob['session_id']}/revoke", headers=h)
    log.info("撤销他人会话响应: %s %s", r.status_code, r.json())
    assert r.status_code == 403
    assert r.json()["error"] == "forbidden"
    bh = {"Authorization": f"Bearer {bob['access_token']}"}
    assert client.get("/resources/doc-1", headers=bh).status_code == 200

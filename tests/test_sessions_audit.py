"""会话自助管理、并发容量限制与安全审计测试。

覆盖：
- 设备说明可选；会话列表字段与最近刷新时间更新
- 并发登录触及容量上限：最终有效数不超限、成败结果与最终状态一致、
  被拒登录不留下可用令牌
- 单会话撤销只影响目标；批量撤销只影响其他会话、当前会话保留
- 撤销当前会话被可区分拒绝（current_session_revoke_denied）且无任何副作用：
  当前访问令牌、刷新链路、其他会话与会话列表均保持原样
- 跨用户撤销 / 撤销不存在的会话 / 查询审计被拒绝
- 审计并发写入不丢不重、分页稳定排序、容量上限淘汰最旧记录
- 各类动作（登录/刷新/登出/撤销/批量/异常终止/密钥轮换/角色调整）均有记录
"""

from __future__ import annotations

import logging
import threading

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.audit import AuditAction, AuditLog
from app.authz import Permission
from app.errors import AuthError, DenyReason
from app.service import AuthService

log = logging.getLogger("test.session")


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
    service.roles.set_role_permissions("auditor", {Permission("audit", "read")})
    service.roles.set_role_permissions(
        "keyadmin", {Permission("keys", "rotate"), Permission("role", "manage")}
    )
    return service


# ------------------------------------------------------------ 设备说明与列表

def test_device_label_optional_and_listed(svc: AuthService) -> None:
    p1 = svc.login("alice", ["reader"], device_label="iPhone 16")
    p2 = svc.login("alice", ["reader"])  # 不传也要正常工作
    infos = svc.list_sessions("alice")
    log.info("会话列表: %s", [(i.session_id[:6], i.device_label, i.status.value) for i in infos])
    assert {i.session_id for i in infos} == {p1.session_id, p2.session_id}
    by_id = {i.session_id: i for i in infos}
    assert by_id[p1.session_id].device_label == "iPhone 16"
    assert by_id[p2.session_id].device_label == ""
    for i in infos:
        assert i.status.value == "active"
        assert i.created_at > 0 and i.last_refreshed_at == i.created_at


def test_last_refreshed_at_advances_on_refresh(svc: AuthService, clock: Clock) -> None:
    pair = svc.login("alice", ["reader"], device_label="cli")
    clock.advance(42)
    rotated = svc.refresh(pair.refresh_token)
    infos = {i.session_id: i for i in svc.list_sessions("alice")}
    info = infos[pair.session_id]
    assert info.last_refreshed_at - info.created_at == 42
    # 刷新后会话仍有效
    assert svc.authorize(rotated.access_token, Permission("document", "read")) == "alice"


# ------------------------------------------------------------ 并发容量上限

def test_login_over_limit_is_distinctly_rejected(svc: AuthService) -> None:
    for _ in range(5):
        svc.login("alice", ["reader"])
    try:
        svc.login("alice", ["reader"], device_label="sixth")
        pytest.fail("第 6 个会话应被拒绝")
    except AuthError as exc:
        log.info("超容量登录拒绝原因: %s", exc.reason.value)
        assert exc.reason is DenyReason.SESSION_LIMIT_REACHED
    # 不挤掉旧会话：仍是 5 个
    assert svc.sessions.active_count("alice") == 5


def test_concurrent_logins_never_exceed_limit(svc: AuthService) -> None:
    threads_n = 40
    barrier = threading.Barrier(threads_n)
    successes: list = []
    failures: list[str] = []
    lock = threading.Lock()

    def worker(idx: int) -> None:
        barrier.wait()
        try:
            pair = svc.login("alice", ["reader"], device_label=f"d{idx}")
            with lock:
                successes.append(pair)
        except AuthError as exc:
            with lock:
                failures.append(exc.reason.value)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(threads_n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final_active = svc.sessions.active_count("alice")
    log.info("并发登录: 请求=%d 成功=%d 拒绝=%d 最终有效=%d",
             threads_n, len(successes), len(failures), final_active)
    assert final_active == 5, "最终有效会话数不能超过上限"
    assert len(successes) == 5, "成功数必须与最终有效数一致"
    assert len(failures) == threads_n - 5
    assert set(failures) == {DenyReason.SESSION_LIMIT_REACHED.value}

    # 所有成功令牌都能用；结果与最终状态一致（不存在"成功但会话不存在"）
    success_ids = set()
    for pair in successes:
        assert svc.authorize(pair.access_token,
                             Permission("document", "read")) == "alice"
        success_ids.add(pair.session_id)
    assert len(success_ids) == 5
    assert {i.session_id for i in svc.list_sessions("alice")} == success_ids


def test_rejected_login_leaves_no_usable_token(svc: AuthService) -> None:
    """达上限后再登录被拒：不存在任何游离令牌，且登出一个后新登录立即成功。"""
    pairs = [svc.login("alice", ["reader"]) for _ in range(5)]
    with pytest.raises(AuthError) as ei:
        svc.login("alice", ["reader"], device_label="ghost")
    assert ei.value.reason is DenyReason.SESSION_LIMIT_REACHED

    # 释放一个名额（撤销），新登录应成功且令牌可用
    svc.revoke_owned_session("alice", pairs[0].session_id)
    fresh = svc.login("alice", ["reader"], device_label="freed-slot")
    assert svc.authorize(fresh.access_token,
                         Permission("document", "read")) == "alice"
    assert svc.sessions.active_count("alice") == 5


def test_capacity_is_per_subject(svc: AuthService) -> None:
    for _ in range(5):
        svc.login("alice", ["reader"])
    # bob 有自己独立的配额
    bob = svc.login("bob", ["reader"])
    assert svc.authorize(bob.access_token,
                         Permission("document", "read")) == "bob"


def test_custom_limit_via_config(clock: Clock) -> None:
    s = AuthService(max_sessions_per_subject=2, now=clock)
    s.login("alice", [])
    s.login("alice", [])
    with pytest.raises(AuthError) as ei:
        s.login("alice", [])
    assert ei.value.reason is DenyReason.SESSION_LIMIT_REACHED


# ------------------------------------------------------------ 撤销隔离

def test_revoke_single_session_isolates_others(svc: AuthService) -> None:
    p1 = svc.login("alice", ["reader"], device_label="a")
    p2 = svc.login("alice", ["reader"], device_label="b")
    p3 = svc.login("alice", ["reader"], device_label="c")
    svc.revoke_owned_session("alice", p2.session_id)

    # 只有 p2 的访问令牌与刷新链路失效
    with pytest.raises(AuthError) as ei:
        svc.authorize(p2.access_token, Permission("document", "read"))
    assert ei.value.reason is DenyReason.TOKEN_REVOKED
    with pytest.raises(AuthError) as ei:
        svc.refresh(p2.refresh_token)
    assert ei.value.reason is DenyReason.TOKEN_REVOKED
    # 其他会话不受影响
    assert svc.authorize(p1.access_token, Permission("document", "read")) == "alice"
    assert svc.authorize(p3.access_token, Permission("document", "read")) == "alice"
    assert svc.refresh(p1.refresh_token).session_id == p1.session_id
    assert svc.sessions.active_count("alice") == 2


def test_revoke_others_keeps_current_session(svc: AuthService) -> None:
    current = svc.login("alice", ["reader"], device_label="current")
    others = [svc.login("alice", ["reader"], device_label=f"o{i}") for i in range(3)]
    revoked = svc.revoke_other_sessions("alice", current.session_id)
    assert {i.session_id for i in revoked} == {p.session_id for p in others}

    # 当前会话及其刷新链路继续有效
    assert svc.authorize(current.access_token,
                         Permission("document", "read")) == "alice"
    rotated = svc.refresh(current.refresh_token)
    assert rotated.session_id == current.session_id
    # 其他会话全部失效
    for p in others:
        with pytest.raises(AuthError) as ei:
            svc.authorize(p.access_token, Permission("document", "read"))
        assert ei.value.reason is DenyReason.TOKEN_REVOKED
    assert svc.sessions.active_count("alice") == 1


def test_cross_user_revoke_is_forbidden(svc: AuthService) -> None:
    alice = svc.login("alice", ["reader"])
    svc.login("bob", ["reader"])
    with pytest.raises(AuthError) as ei:
        svc.revoke_owned_session("bob", alice.session_id)
    assert ei.value.reason is DenyReason.FORBIDDEN
    # 被拒后 alice 会话仍然有效
    assert svc.authorize(alice.access_token,
                         Permission("document", "read")) == "alice"


# ------------------------------------------------------------ 当前会话撤销保护

def test_revoke_current_session_is_denied_without_side_effects(svc: AuthService) -> None:
    """撤销当前会话必须被可区分地拒绝，且当前令牌、刷新链路、其他会话均不受影响。"""
    current = svc.login("alice", ["reader"], device_label="current")
    other = svc.login("alice", ["reader"], device_label="other")
    before = [i.session_id for i in svc.list_sessions("alice")]

    with pytest.raises(AuthError) as ei:
        svc.revoke_owned_session("alice", current.session_id,
                                 current_session_id=current.session_id)
    log.info("撤销当前会话拒绝原因: %s", ei.value.reason.value)
    assert ei.value.reason is DenyReason.CURRENT_SESSION_REVOKE

    # 无副作用：当前访问令牌仍可用
    assert svc.authorize(current.access_token,
                         Permission("document", "read")) == "alice"
    # 当前会话整条刷新链路仍可用
    rotated = svc.refresh(current.refresh_token)
    assert rotated.session_id == current.session_id
    assert svc.authorize(rotated.access_token,
                         Permission("document", "read")) == "alice"
    # 其他会话不被连带失效
    assert svc.authorize(other.access_token,
                         Permission("document", "read")) == "alice"
    # 会话列表如实反映：两个会话都仍是 active
    after = svc.list_sessions("alice")
    assert [i.session_id for i in after] == before
    assert all(i.status.value == "active" for i in after)
    # 拒绝本身留有审计记录
    records = svc.audit.query(subject="alice",
                              actions={AuditAction.SESSION_REVOKE}, limit=100).items
    assert any(r.result == f"denied:{DenyReason.CURRENT_SESSION_REVOKE.value}"
               and r.session_id == current.session_id for r in records)


def test_revoke_other_session_with_current_context_still_works(svc: AuthService) -> None:
    """带上当前会话标识去撤销其他会话：正常生效且不影响当前会话。"""
    current = svc.login("alice", ["reader"], device_label="current")
    other = svc.login("alice", ["reader"], device_label="other")

    info = svc.revoke_owned_session("alice", other.session_id,
                                    current_session_id=current.session_id)
    assert info.session_id == other.session_id
    assert info.status.value == "revoked"

    # 被撤销会话的访问令牌与刷新链路失效
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
    assert [i.session_id for i in svc.list_sessions("alice")] == [current.session_id]


def test_revoke_nonexistent_session_still_denied(svc: AuthService) -> None:
    current = svc.login("alice", ["reader"])
    with pytest.raises(AuthError) as ei:
        svc.revoke_owned_session("alice", "no-such-session",
                                 current_session_id=current.session_id)
    log.info("撤销不存在会话拒绝原因: %s", ei.value.reason.value)
    assert ei.value.reason is DenyReason.SESSION_NOT_FOUND
    # 当前会话不受影响
    assert svc.authorize(current.access_token,
                         Permission("document", "read")) == "alice"


# ------------------------------------------------------------ 审计记录内容

def test_all_security_actions_are_audited(svc: AuthService, clock: Clock) -> None:
    p = svc.login("alice", ["reader"], device_label="dev")
    clock.advance(1)
    rotated = svc.refresh(p.refresh_token)
    # 重放旧刷新令牌 -> 会话因异常刷新终止
    with pytest.raises(AuthError):
        svc.refresh(p.refresh_token)
    svc.revoke_owned_session("alice", rotated.session_id)

    current = svc.login("alice", ["reader"], device_label="cur")
    svc.login("alice", ["reader"], device_label="other")
    svc.revoke_other_sessions("alice", current.session_id)

    svc.rotate_keys()
    svc.set_role_permissions("reader", {Permission("document", "read")})
    svc.logout(svc.login("carol", ["reader"]).access_token)

    page = svc.audit.query(limit=1000)
    actions = {r.action for r in page.items}
    log.info("审计动作集合: %s", sorted(a.value for a in actions))
    for a in AuditAction:
        assert a in actions, f"缺少动作 {a.value} 的审计记录"
    # 每条记录必备字段
    for r in page.items:
        assert r.seq > 0 and r.timestamp > 0 and r.subject and r.result


def test_rejected_login_and_refresh_audited(svc: AuthService) -> None:
    pairs = [svc.login("alice", ["reader"]) for _ in range(5)]
    with pytest.raises(AuthError):
        svc.login("alice", ["reader"])
    # 重放导致会话异常终止
    svc.refresh(pairs[0].refresh_token)
    with pytest.raises(AuthError):
        svc.refresh(pairs[0].refresh_token)

    logins = svc.audit.query(actions={AuditAction.LOGIN}, limit=1000).items
    denied = [r for r in logins if r.result.startswith("denied:")]
    assert denied and denied[0].result.endswith(DenyReason.SESSION_LIMIT_REACHED.value)

    terms = svc.audit.query(actions={AuditAction.SESSION_TERMINATED}, limit=1000).items
    assert len(terms) == 1 and terms[0].session_id == pairs[0].session_id

    refreshes = svc.audit.query(actions={AuditAction.REFRESH}, limit=1000).items
    assert any(r.result == "success" for r in refreshes)
    assert any(DenyReason.REFRESH_REUSED.value in r.result for r in refreshes)


# ------------------------------------------------------------ 审计并发完整性

def test_concurrent_audit_writes_no_loss_no_dup() -> None:
    audit = AuditLog(max_records=100_000)
    n_threads, per_thread = 16, 200
    barrier = threading.Barrier(n_threads)

    def worker() -> None:
        barrier.wait()
        for _ in range(per_thread):
            audit.append("alice", AuditAction.LOGIN, "success")

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    page = audit.query(limit=1_000_000)
    seqs = [r.seq for r in page.items]
    assert page.total == n_threads * per_thread
    assert len(set(seqs)) == len(seqs), "序号不得重复"
    assert seqs == sorted(seqs), "必须按序号稳定排序"
    assert seqs[0] == 1 and seqs[-1] == len(seqs), "序号连续无丢失"


def test_audit_capacity_evicts_oldest() -> None:
    audit = AuditLog(max_records=10)
    for i in range(15):
        audit.append("alice", AuditAction.LOGIN, "success", detail=str(i))
    page = audit.query(limit=100)
    assert page.total == 10, "容量有界，恒定不超过上限"
    # 淘汰的是最旧记录：保留 detail 5..14（序号 6..15）
    assert [r.detail for r in page.items] == [str(i) for i in range(5, 15)]
    # 全局序号仍单调递增、不复用
    assert page.items[0].seq == 6 and page.items[-1].seq == 15


def test_audit_pagination_and_filters_are_stable(svc: AuthService) -> None:
    svc.login("alice", ["reader"])
    svc.login("alice", ["reader"])
    svc.login("bob", ["reader"])

    # 分页：两页拼起来等于全集，顺序稳定
    p1 = svc.audit.query(limit=2, offset=0)
    p2 = svc.audit.query(limit=2, offset=2)
    all_page = svc.audit.query(limit=100)
    assert p1.total == all_page.total
    assert [r.seq for r in p1.items] + [r.seq for r in p2.items] == \
           [r.seq for r in all_page.items][:4]

    # 主体过滤
    alice_logins = svc.audit.query(subject="alice", limit=100)
    assert all(r.subject == "alice" for r in alice_logins.items)
    assert alice_logins.total == 2

    # 时间范围（闭区间）
    t = svc.audit.query(limit=1).items[0].timestamp
    assert svc.audit.query(start=t, end=t, limit=100).total == all_page.total


def test_key_rotation_refresh_denial_is_audited(svc: AuthService) -> None:
    p = svc.login("alice", ["reader"])
    svc.rotate_keys()
    with pytest.raises(AuthError) as ei:
        svc.refresh(p.refresh_token)
    assert ei.value.reason is DenyReason.TOKEN_REVOKED
    refreshes = svc.audit.query(
        subject="alice", actions={AuditAction.REFRESH}, limit=1000
    ).items
    assert any(DenyReason.TOKEN_REVOKED.value in r.result for r in refreshes)


def test_normal_user_cannot_query_others_audit(svc: AuthService) -> None:
    svc.login("alice", ["reader"])
    bob = svc.login("bob", ["reader"])
    # 无 subject 参数：强制收敛为自己
    own = svc.query_audit("bob")
    assert all(r.subject == "bob" for r in own.items)
    # 指定他人：拒绝
    with pytest.raises(AuthError) as ei:
        svc.query_audit("bob", subject="alice")
    assert ei.value.reason is DenyReason.FORBIDDEN
    # 具备 audit:read 可查全部
    admin = svc.login("admin", ["auditor"])
    page = svc.query_audit("admin", subject="alice")
    assert page.total >= 1 and all(r.subject == "alice" for r in page.items)


# ------------------------------------------------------------ HTTP 层

def test_http_revoke_current_session_denied_and_state_consistent(svc: AuthService) -> None:
    """HTTP 端到端：撤销当前会话被 409 拒绝，且当前令牌/刷新链路/会话列表全部保持一致。"""
    client = TestClient(create_app(svc))

    def login(subject, roles, label=None):
        body = {"subject": subject, "roles": roles}
        if label is not None:
            body["device_label"] = label
        r = client.post("/login", json=body)
        assert r.status_code == 200, r.text
        return r.json()

    current = login("alice", ["reader"], "current")
    other = login("alice", ["reader"], "other")
    h = {"Authorization": f"Bearer {current['access_token']}"}

    # 撤销当前会话 -> 409，原因稳定可区分
    r = client.post(f"/sessions/{current['session_id']}/revoke", headers=h)
    log.info("HTTP 撤销当前会话: status=%d body=%s", r.status_code, r.json())
    assert r.status_code == 409
    assert r.json()["error"] == "current_session_revoke_denied"

    # 无副作用：同一访问令牌访问受保护资源仍然 200
    r = client.get("/resources/doc-1", headers=h)
    assert r.status_code == 200 and r.json()["subject"] == "alice"
    # 刷新链路仍然可用
    r = client.post("/refresh", json={"refresh_token": current["refresh_token"]})
    assert r.status_code == 200 and r.json()["session_id"] == current["session_id"]
    # 会话列表如实反映：两个会话都仍 active
    listed = client.get("/sessions", headers=h).json()["sessions"]
    assert {s["session_id"] for s in listed} == {current["session_id"], other["session_id"]}
    assert all(s["status"] == "active" for s in listed)

    # 撤销自己的其他会话 -> 200 生效，当前会话不受影响
    r = client.post(f"/sessions/{other['session_id']}/revoke", headers=h)
    assert r.status_code == 200 and r.json()["session"]["status"] == "revoked"
    assert client.get("/resources/doc-1", headers=h).status_code == 200
    oh = {"Authorization": f"Bearer {other['access_token']}"}
    assert client.get("/resources/doc-1", headers=oh).status_code == 401
    listed = client.get("/sessions", headers=h).json()["sessions"]
    assert [s["session_id"] for s in listed] == [current["session_id"]]

    # 撤销不存在的会话 -> 401 session_not_found（可区分）
    r = client.post("/sessions/no-such-session/revoke", headers=h)
    assert r.status_code == 401 and r.json()["error"] == "session_not_found"

    # 撤销他人会话 -> 403 forbidden，且目标会话不被波及（不泄漏、不失效）
    bob = login("bob", ["reader"], "bob-dev")
    r = client.post(f"/sessions/{bob['session_id']}/revoke", headers=h)
    assert r.status_code == 403 and r.json()["error"] == "forbidden"
    bh = {"Authorization": f"Bearer {bob['access_token']}"}
    assert client.get("/resources/doc-1", headers=bh).status_code == 200


def test_http_session_and_audit_flows(svc: AuthService) -> None:
    client = TestClient(create_app(svc))

    def login(subject, roles, label=None):
        body = {"subject": subject, "roles": roles}
        if label is not None:
            body["device_label"] = label
        r = client.post("/login", json=body)
        assert r.status_code == 200, r.text
        return r.json()

    first = login("alice", ["reader"], "browser")
    for i in range(4):
        login("alice", ["reader"], f"tab-{i}")
    # 第 6 个 -> 409 稳定可区分
    r = client.post("/login", json={"subject": "alice", "roles": ["reader"]})
    assert r.status_code == 409 and r.json()["error"] == "session_limit_reached"

    h = {"Authorization": f"Bearer {first['access_token']}"}
    listed = client.get("/sessions", headers=h).json()["sessions"]
    assert len(listed) == 5
    labels = {s["device_label"] for s in listed}
    assert labels == {"browser", "tab-0", "tab-1", "tab-2", "tab-3"}
    # 列表字段完整
    for s in listed:
        assert {"session_id", "created_at", "last_refreshed_at",
                "status", "device_label"} <= set(s)

    # 无令牌 -> 401
    assert client.get("/sessions").status_code == 401

    # 批量撤销其他，保留当前
    r = client.post("/sessions/revoke-others", headers=h)
    assert r.status_code == 200 and r.json()["kept"] == first["session_id"]
    assert len(r.json()["revoked"]) == 4
    assert client.get("/sessions", headers=h).status_code == 200  # 当前仍可用

    # 普通用户查他人审计 -> 403；查自己 -> 200
    bob = login("bob", ["reader"], "bb")
    bh = {"Authorization": f"Bearer {bob['access_token']}"}
    assert client.get("/audit?subject=alice", headers=bh).status_code == 403
    mine = client.get("/audit", headers=bh).json()
    assert all(i["subject"] == "bob" for i in mine["items"])

    # 审计员查询 + 动作过滤 + 分页
    aud = login("aud", ["auditor"], "audit-console")
    ah = {"Authorization": f"Bearer {aud['access_token']}"}
    r = client.get("/audit?action=login&limit=3&offset=0", headers=ah)
    assert r.status_code == 200
    assert len(r.json()["items"]) == 3 and all(i["action"] == "login" for i in r.json()["items"])
    # 容量拒绝的登录也在审计里
    logins = client.get("/audit?action=login&limit=100", headers=ah).json()["items"]
    assert any("session_limit_reached" in i["result"] for i in logins)

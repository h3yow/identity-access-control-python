"""会话自助管理、并发容量限制与安全审计的测试。

覆盖：
- 设备标识（可缺省）、会话列表字段、单会话/批量撤销、当前会话保护；
- 并发登录触及容量上限（不超限、无半成功、结果与最终状态一致）；
- 审计并发写入完整性、容量清理、过滤+稳定排序+分页、查询权限范围；
- 普通用户查询/撤销他人会话与审计记录被拒绝；
- 刷新轮换/重放、密钥轮换、权限即时生效等既有用例不回归。
"""

from __future__ import annotations

import logging
import threading

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.audit import AuditAction, AuditLog, AuditQuery
from app.authz import Permission
from app.errors import AuthError, DenyReason
from app.service import AuthService

log = logging.getLogger("test.sessions")


class Clock:
    def __init__(self, t: int = 2_000_000) -> None:
        self.t = t

    def __call__(self) -> int:
        return self.t

    def advance(self, seconds: int) -> None:
        self.t += seconds


def outcome(fn, *args, **kwargs) -> str:
    try:
        fn(*args, **kwargs)
        return "allow"
    except AuthError as exc:
        return exc.reason.value


@pytest.fixture()
def clock() -> Clock:
    return Clock()


@pytest.fixture()
def svc(clock: Clock) -> AuthService:
    service = AuthService(
        access_ttl=300,
        refresh_ttl=3600,
        max_sessions_per_subject=5,
        audit_max_entries=10_000,
        now=clock,
    )
    service.roles.set_role_permissions("reader", {Permission("document", "read")})
    service.roles.set_role_permissions("auditor", {Permission("session", "manage")})
    service.roles.set_role_permissions(
        "admin",
        {Permission("keys", "rotate"), Permission("role", "manage")},
    )
    return service


# --------------------------------------------------------- 设备标识与会话列表

def test_login_device_optional_and_session_fields(svc: AuthService) -> None:
    p_phone = svc.login("alice", ["reader"], "iPhone 17")
    p_plain = svc.login("alice", ["reader"])  # 不传设备说明也正常

    infos = svc.list_my_sessions(p_phone.access_token)
    log.info("会话列表: %s", [(i.session_id[:4], i.device, i.status) for i in infos])
    assert len(infos) == 2
    by_id = {i.session_id: i for i in infos}
    assert by_id[p_phone.session_id].device == "iPhone 17"
    assert by_id[p_plain.session_id].device == ""
    for info in infos:
        assert info.status == "active"
        assert info.created_at > 0
        assert info.last_refreshed_at >= info.created_at


def test_refresh_updates_last_refreshed_time(svc: AuthService, clock: Clock) -> None:
    pair = svc.login("alice", ["reader"], "phone")
    clock.advance(60)
    rotated = svc.refresh(pair.refresh_token)
    info = next(i for i in svc.list_my_sessions(rotated.access_token)
                if i.session_id == pair.session_id)
    assert info.last_refreshed_at == clock.t > info.created_at


# --------------------------------------------------------- 单会话撤销隔离

def test_revoke_single_session_only_affects_target(svc: AuthService) -> None:
    a = svc.login("alice", ["reader"], "a")
    b = svc.login("alice", ["reader"], "b")
    c = svc.login("alice", ["reader"], "c")

    svc.revoke_my_session(a.access_token, b.session_id)
    log.info("撤销会话 b 后检查 a/c 是否不受影响")

    assert outcome(svc.authorize, b.access_token,
                   Permission("document", "read")) == DenyReason.TOKEN_REVOKED.value
    assert outcome(svc.refresh, b.refresh_token) == DenyReason.TOKEN_REVOKED.value
    # 其他会话的访问与刷新链路均保持有效
    assert svc.authorize(a.access_token, Permission("document", "read")) == "alice"
    assert svc.authorize(c.access_token, Permission("document", "read")) == "alice"
    refreshed = svc.refresh(a.refresh_token)
    assert svc.authorize(refreshed.access_token, Permission("document", "read")) == "alice"

    remaining = {i.session_id for i in svc.list_my_sessions(refreshed.access_token)}
    assert remaining == {a.session_id, c.session_id}


def test_cannot_revoke_current_session(svc: AuthService) -> None:
    pair = svc.login("alice", ["reader"], "a")
    reason = outcome(svc.revoke_my_session, pair.access_token, pair.session_id)
    log.info("撤销当前会话 -> %s", reason)
    assert reason == DenyReason.FORBIDDEN.value
    # 当前会话仍然有效
    assert svc.authorize(pair.access_token, Permission("document", "read")) == "alice"


def test_user_cannot_revoke_other_users_session(svc: AuthService) -> None:
    a = svc.login("alice", ["reader"], "a")
    bob = svc.login("bob", ["reader"], "b")
    # bob 无法获知/撤销 alice 的会话标识：一律 not_found，不泄漏存在性
    reason = outcome(svc.revoke_my_session, bob.access_token, a.session_id)
    assert reason == DenyReason.SESSION_NOT_FOUND.value
    assert svc.authorize(a.access_token, Permission("document", "read")) == "alice"


# --------------------------------------------------------- 批量撤销隔离

def test_revoke_others_only_affects_target_sessions(svc: AuthService) -> None:
    a = svc.login("alice", ["reader"], "a")
    b = svc.login("alice", ["reader"], "b")
    c = svc.login("alice", ["reader"], "c")
    # 其他用户的会话绝不受影响
    x = svc.login("bob", ["reader"], "x")

    current = svc.refresh(a.refresh_token)  # 当前会话经一次刷新
    revoked = svc.revoke_other_sessions(current.access_token)
    log.info("批量撤销目标: %s", [sid[:4] for sid in revoked])

    assert set(revoked) == {b.session_id, c.session_id}
    for victim in (b, c):
        assert outcome(svc.authorize, victim.access_token,
                       Permission("document", "read")) == DenyReason.TOKEN_REVOKED.value
        assert outcome(svc.refresh, victim.refresh_token) == DenyReason.TOKEN_REVOKED.value
    # 当前会话（含刷新后的新链路）与其他用户会话均保持有效
    assert svc.authorize(current.access_token, Permission("document", "read")) == "alice"
    again = svc.refresh(current.refresh_token)
    assert svc.authorize(again.access_token, Permission("document", "read")) == "alice"
    assert svc.authorize(x.access_token, Permission("document", "read")) == "bob"
    remaining = {i.session_id for i in svc.list_my_sessions(current.access_token)}
    assert remaining == {a.session_id}


# --------------------------------------------------------- 容量限制

def test_login_rejected_at_capacity_without_half_open_state(svc: AuthService) -> None:
    pairs = [svc.login("alice", ["reader"], f"d{i}") for i in range(5)]
    denied = outcome(svc.login, "alice", ["reader"], "sixth")
    log.info("第 6 个登录 -> %s", denied)
    assert denied == DenyReason.SESSION_LIMIT_REACHED.value

    # 最终有效会话数恰好为上限
    assert len(svc.list_my_sessions(pairs[0].access_token)) == 5
    # 被拒登录没有产生可用令牌：容量腾出后再登录成功，且旧 5 个仍在
    svc.revoke_my_session(pairs[0].access_token, pairs[-1].session_id)
    fresh = svc.login("alice", ["reader"], "new")
    assert svc.authorize(fresh.access_token, Permission("document", "read")) == "alice"
    active = svc.list_my_sessions(fresh.access_token)
    assert len(active) == 5


def test_capacity_is_per_subject(svc: AuthService) -> None:
    for i in range(5):
        svc.login("alice", ["reader"], f"a{i}")
    # 另一用户独立计数，不受影响
    bob = svc.login("bob", ["reader"], "b0")
    assert svc.authorize(bob.access_token, Permission("document", "read")) == "bob"


def test_capacity_configurable() -> None:
    small = AuthService(max_sessions_per_subject=2, audit_max_entries=100)
    small.roles.set_role_permissions("reader", {Permission("document", "read")})
    small.login("u", ["reader"])
    small.login("u", ["reader"])
    assert outcome(small.login, "u", ["reader"]) == DenyReason.SESSION_LIMIT_REACHED.value


def test_concurrent_logins_never_exceed_capacity() -> None:
    service = AuthService(max_sessions_per_subject=5, audit_max_entries=100_000)
    service.roles.set_role_permissions("reader", {Permission("document", "read")})
    results: list[tuple[str, object]] = []
    barrier = threading.Barrier(32)

    def worker() -> None:
        barrier.wait()
        try:
            pair = service.login("alice", ["reader"], "concurrent")
            results.append(("ok", pair))
        except AuthError as exc:
            results.append((exc.reason.value, None))

    threads = [threading.Thread(target=worker) for _ in range(32)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    oks = [r for r in results if r[0] == "ok"]
    rejects = [r for r in results if r[0] != "ok"]
    log.info("并发登录 32 个: 成功=%d 拒绝=%d", len(oks), len(rejects))
    assert len(oks) == 5
    assert len({r[1].session_id for r in oks}) == 5
    assert all(r[0] == DenyReason.SESSION_LIMIT_REACHED.value for r in rejects)
    # 最终有效会话数与成功结果一致
    token = oks[0][1].access_token
    assert len(service.list_my_sessions(token)) == 5
    # 每个成功登录的令牌都仍可使用；不存在被拒但令牌残留可用的情况
    for r in oks:
        assert service.authorize(r[1].access_token,
                                 Permission("document", "read")) == "alice"


# --------------------------------------------------------- 审计：并发写入完整性

def test_audit_concurrent_writes_no_loss_or_duplicate() -> None:
    audit = AuditLog(max_entries=1_000_000)
    threads_n, per_thread = 24, 250
    barrier = threading.Barrier(threads_n)

    def worker() -> None:
        barrier.wait()
        for i in range(per_thread):
            audit.record("alice", AuditAction.LOGIN, "ok", detail=str(i))

    threads = [threading.Thread(target=worker) for _ in range(threads_n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    page = audit.query(AuditQuery(limit=1_000_000))
    seqs = [e.seq for e in page.items]
    assert page.total == threads_n * per_thread
    assert len(seqs) == len(set(seqs)), "seq 不得重复"
    assert sorted(seqs) == list(range(1, len(seqs) + 1)), "seq 必须连续不丢失"


def test_audit_capacity_bound_drops_oldest(clock: Clock) -> None:
    audit = AuditLog(max_entries=3, now=clock)
    first = audit.record("alice", AuditAction.LOGIN, "ok")
    for _ in range(4):
        clock.advance(1)
        audit.record("alice", AuditAction.LOGIN, "ok")
    page = audit.query(AuditQuery(limit=100))
    assert page.total == 3
    assert all(e.seq > first.seq for e in page.items), "超容量后只保留最新记录"


# --------------------------------------------------------- 审计：过滤/排序/分页

def test_audit_filter_sort_and_pagination(clock: Clock) -> None:
    audit = AuditLog(max_entries=1000, now=clock)
    for i in range(6):
        clock.advance(1)
        audit.record("alice", AuditAction.LOGIN if i % 2 == 0 else AuditAction.LOGOUT,
                     "ok")
    clock.advance(1)
    audit.record("bob", AuditAction.LOGIN, "ok")

    # 时间升序、同时间 seq 升序的稳定排序
    items = audit.query(AuditQuery(limit=100)).items
    keys = [(e.timestamp, e.seq) for e in items]
    assert keys == sorted(keys)

    # 主体 + 动作过滤
    alice_logins = audit.query(
        AuditQuery(subject="alice", action=AuditAction.LOGIN, limit=100)
    )
    assert alice_logins.total == 3
    assert all(e.subject == "alice" and e.action is AuditAction.LOGIN
               for e in alice_logins.items)

    # 时间范围
    window = audit.query(AuditQuery(start=clock.t, end=clock.t, limit=100))
    assert window.total == 1 and window.items[0].subject == "bob"

    # 分页稳定：逐页拼接与一次性查询一致
    paged: list = []
    for offset in range(0, 7, 3):
        p = audit.query(AuditQuery(offset=offset, limit=3))
        paged.extend(p.items)
    full = audit.query(AuditQuery(limit=100)).items
    assert [e.seq for e in paged] == [e.seq for e in full]


# --------------------------------------------------------- 审计：动作覆盖

def test_audit_records_all_security_actions(clock: Clock) -> None:
    service = AuthService(
        max_sessions_per_subject=5, audit_max_entries=10_000, now=clock
    )
    service.roles.set_role_permissions("reader", {Permission("document", "read")})
    service.roles.set_role_permissions(
        "admin", {Permission("keys", "rotate"), Permission("role", "manage")}
    )

    # 打满容量后第 6 次登录被拒，拒绝也要落审计
    for i in range(5):
        service.login("alice", ["reader"], f"d{i}")
    assert outcome(service.login, "alice", ["reader"], "sixth") == \
        DenyReason.SESSION_LIMIT_REACHED.value

    # 另一用户：刷新成功/拒绝、单会话撤销、批量撤销、登出
    a = service.login("bob", ["reader"], "browser")
    rotated = service.refresh(a.refresh_token)
    other = service.login("bob", ["reader"], "mobile")
    service.revoke_my_session(rotated.access_token, other.session_id)
    keep = service.refresh(rotated.refresh_token)
    service.revoke_other_sessions(keep.access_token)
    service.logout(keep.access_token)

    # 管理员：密钥轮换、角色权限调整
    admin = service.login("root", ["admin", "reader"])
    service.rotate_keys(admin.access_token)
    admin2 = service.login("root", ["admin", "reader"])
    service.set_role_permissions(
        admin2.access_token, "reader", {Permission("document", "read")}
    )

    page = service.audit.query(AuditQuery(limit=1000))
    actions = {e.action for e in page.items}
    for expected in (
        AuditAction.LOGIN,
        AuditAction.LOGIN_REJECTED,
        AuditAction.REFRESH,
        AuditAction.LOGOUT,
        AuditAction.SESSION_REVOKE,
        AuditAction.SESSIONS_REVOKE_OTHERS,
        AuditAction.KEY_ROTATE,
        AuditAction.ROLE_PERMISSIONS_CHANGE,
    ):
        assert expected in actions, f"缺少审计动作 {expected}"
    rejected = [e for e in page.items if e.action is AuditAction.LOGIN_REJECTED]
    assert rejected and rejected[0].result == DenyReason.SESSION_LIMIT_REACHED.value
    assert rejected[0].session_id is None


def test_audit_records_refresh_rejection_and_termination(clock: Clock) -> None:
    service = AuthService(max_sessions_per_subject=5, now=clock)
    service.roles.set_role_permissions("reader", {Permission("document", "read")})
    pair = service.login("bob", ["reader"])
    rotated = service.refresh(pair.refresh_token)
    # 重放：产生 refresh_rejected + session_terminated 两条记录
    assert outcome(service.refresh, pair.refresh_token) == \
        DenyReason.REFRESH_REUSED.value
    page = service.audit.query(AuditQuery(limit=100))
    results = {(e.action, e.result) for e in page.items}
    assert (AuditAction.REFRESH_REJECTED, DenyReason.REFRESH_REUSED.value) in results
    assert (AuditAction.SESSION_TERMINATED, DenyReason.REFRESH_REUSED.value) in results
    # 重放后胜者凭据同样失效（既有语义不回归）
    assert outcome(service.authorize, rotated.access_token,
                   Permission("document", "read")) == DenyReason.REFRESH_REUSED.value


# --------------------------------------------------------- 审计：查询权限范围

def test_normal_user_sees_only_own_audit(svc: AuthService) -> None:
    alice = svc.login("alice", ["reader"], "a")
    svc.login("bob", ["reader"], "b")
    # 即使显式带上他人 subject，也被强制收敛到自己
    page = svc.query_audit(
        alice.access_token, AuditQuery(subject="bob", limit=100)
    )
    assert page.items, "至少有 alice 自己的登录记录"
    assert all(e.subject == "alice" for e in page.items)


def test_privileged_role_can_query_all_with_filters(svc: AuthService) -> None:
    svc.login("alice", ["reader"], "a")
    root = svc.login("root", ["auditor"])
    page = svc.query_audit(
        root.access_token,
        AuditQuery(subject="alice", action=AuditAction.LOGIN, limit=100),
    )
    assert page.total >= 1
    assert all(e.subject == "alice" and e.action is AuditAction.LOGIN
               for e in page.items)
    # 不带 subject 时可见全部主体
    all_page = svc.query_audit(root.access_token, AuditQuery(limit=1000))
    assert {e.subject for e in all_page.items} >= {"alice", "root"}


# --------------------------------------------------------- HTTP 层

def test_http_capacity_rejection_is_stable_409(svc: AuthService) -> None:
    client = TestClient(create_app(svc))
    for i in range(5):
        assert client.post("/login", json={
            "subject": "alice", "roles": ["reader"], "device": f"d{i}"
        }).status_code == 200
    r = client.post("/login", json={"subject": "alice", "roles": ["reader"]})
    assert r.status_code == 409
    assert r.json()["error"] == "session_limit_reached"

    # 被拒登录后既有 5 个会话仍在，且第 6 次同样被稳定拒绝（错误码可区分）
    first = client.post("/login", json={
        "subject": "alice", "roles": ["reader"], "device": "again"
    })
    assert first.status_code == 409
    # 撤销一个会话腾出容量后，新登录成功（拒绝不残留任何状态）
    a = client.post("/login", json={"subject": "probe", "roles": ["reader"]}).json()
    hp = {"Authorization": f"Bearer {a['access_token']}"}
    assert client.post("/sessions/revoke-others", headers=hp).status_code == 200


def test_http_self_service_and_audit_scope(svc: AuthService) -> None:
    client = TestClient(create_app(svc))
    a = client.post("/login", json={
        "subject": "alice", "roles": ["reader"], "device": "phone"
    }).json()
    b = client.post("/login", json={
        "subject": "alice", "roles": ["reader"], "device": "laptop"
    }).json()
    ha = {"Authorization": f"Bearer {a['access_token']}"}
    hb = {"Authorization": f"Bearer {b['access_token']}"}

    listed = client.get("/sessions", headers=ha).json()["sessions"]
    assert {s["session_id"] for s in listed} == {a["session_id"], b["session_id"]}

    # 撤销当前会话 -> 403
    r = client.post(f"/sessions/{a['session_id']}/revoke", headers=ha)
    assert r.status_code == 403
    # alice 撤销 b
    r = client.post(f"/sessions/{b['session_id']}/revoke", headers=ha)
    assert r.status_code == 200
    assert client.get("/resources/doc-1", headers=hb).status_code == 401
    assert client.get("/resources/doc-1", headers=ha).status_code == 200

    # 普通用户审计只看到自己
    items = client.get("/audit?limit=100", headers=ha).json()["items"]
    assert all(i["subject"] == "alice" for i in items)
    assert any(i["action"] == "session_revoke" for i in items)


# --------------------------------------------------------- HTTP 层越权访问

def test_http_cross_user_revoke_and_audit_are_denied(svc: AuthService) -> None:
    client = TestClient(create_app(svc))
    a = client.post("/login", json={
        "subject": "alice", "roles": ["reader"], "device": "phone"
    }).json()
    b = client.post("/login", json={
        "subject": "bob", "roles": ["reader"], "device": "pc"
    }).json()
    hb = {"Authorization": f"Bearer {b['access_token']}"}

    # bob 撤销 alice 的会话 -> 401 session_not_found，alice 会话不受影响
    r = client.post(f"/sessions/{a['session_id']}/revoke", headers=hb)
    assert r.status_code == 401 and r.json()["error"] == "session_not_found"
    ha = {"Authorization": f"Bearer {a['access_token']}"}
    assert client.get("/resources/doc-1", headers=ha).status_code == 200

    # bob 带 subject=alice 查询审计 -> 结果被强制收敛为 bob 自己
    page = client.get("/audit?subject=alice&limit=100", headers=hb).json()
    assert page["items"]
    assert all(i["subject"] == "bob" for i in page["items"])


def test_audit_pagination_is_stable_under_concurrent_reads() -> None:
    service = AuthService(max_sessions_per_subject=100, audit_max_entries=1_000_000)
    service.roles.set_role_permissions("reader", {Permission("document", "read")})
    for i in range(37):
        service.login("alice", ["reader"], f"d{i}")

    pages: list[list[int]] = []

    def fetch(offset: int) -> None:
        page = service.audit.query(AuditQuery(subject="alice", offset=offset, limit=10))
        pages.append([e.seq for e in page.items])

    threads = [threading.Thread(target=fetch, args=(off,))
               for off in range(0, 40, 10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    pages.sort(key=lambda p: p[0])
    seqs = [s for p in pages for s in p]
    assert seqs == sorted(set(seqs))  # 各页不重不缺、顺序稳定

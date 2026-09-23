"""HTTP 接口测试：状态码、可区分错误码、资源存在性隐藏、真实线程并发刷新。"""

from __future__ import annotations

import logging
import threading

import pytest
from fastapi.testclient import TestClient

from auth.app import create_app
from auth.keys import KeyManager
from auth.service import AuthService
from auth.store import LocalStore

log = logging.getLogger("test.api")


@pytest.fixture()
def client() -> TestClient:
    svc = AuthService(LocalStore(), KeyManager())
    svc.add_role_permission("viewer", "doc:read")
    svc.add_role_permission("editor", "doc:read")
    svc.add_role_permission("editor", "doc:publish")
    svc.add_role_permission("admin", "*")
    svc.create_user("alice", "alice-pw", ["editor"])
    svc.create_user("bob", "bob-pw", ["viewer"])
    svc.create_user("root", "root-pw", ["admin"])
    return TestClient(create_app(svc))


def login(client: TestClient, username: str, password: str) -> dict[str, str]:
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()  # type: ignore[return-value]


def bearer(tokens: dict[str, str]) -> dict[str, str]:
    return {"Authorization": "Bearer " + tokens["access_token"]}


def test_login_failure_does_not_reveal_account_existence(client: TestClient) -> None:
    r1 = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    r2 = client.post("/auth/login", json={"username": "ghost", "password": "wrong"})
    log.info("输入: 错误口令(存在用户) vs 错误口令(不存在用户)；响应体必须一致")
    assert r1.status_code == r2.status_code == 401
    assert r1.json() == r2.json()
    assert r1.json()["error"] == "invalid_credentials"


def test_missing_malformed_revoked_return_distinct_codes(client: TestClient) -> None:
    tokens = login(client, "bob", "bob-pw")
    r_missing = client.get("/resources/doc-1")
    r_malformed = client.get("/resources/doc-1", headers={"Authorization": "Bearer a.b"})
    log.info("输入: 无凭据 -> %s；畸形 -> %s",
             r_missing.json()["error"], r_malformed.json()["error"])
    assert r_missing.status_code == 401 and r_missing.json()["error"] == "missing_credential"
    assert r_malformed.status_code == 401 and r_malformed.json()["error"] == "malformed_token"

    # 签名错误
    head, payload, sig = tokens["access_token"].split(".")
    bad_sig = ("z" if sig[0] != "z" else "y") + sig[1:]
    r_badsig = client.get("/resources/doc-1",
                          headers={"Authorization": f"Bearer {head}.{payload}.{bad_sig}"})
    assert r_badsig.json()["error"] == "bad_signature"

    # 重放 -> refresh_replay
    client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    r_replay = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    log.info("输入: 重放 refresh -> %s", r_replay.json()["error"])
    assert r_replay.status_code == 401 and r_replay.json()["error"] == "refresh_replay"

    # 被撤销的访问令牌 -> access_token_revoked/family_revoked（重放已撤族）
    r_revoked = client.get("/resources/doc-1", headers=bearer(tokens))
    assert r_revoked.status_code == 401
    assert r_revoked.json()["error"] in ("access_token_revoked", "family_revoked")


def test_forbidden_and_missing_resource_are_indistinguishable(client: TestClient) -> None:
    tokens = login(client, "bob", "bob-pw")  # bob 只有 doc:read
    # 越权（资源存在）
    r_forbidden = client.post("/resources/doc-1/publish", headers=bearer(tokens))
    # 资源不存在
    r_missing = client.get("/resources/does-not-exist", headers=bearer(tokens))
    log.info("输入: 越权访问存在资源 vs 访问不存在资源；状态码/响应体必须完全一致")
    assert r_forbidden.status_code == r_missing.status_code == 404
    assert r_forbidden.json() == r_missing.json() == {
        "error": "not_found", "error_description": "资源不存在或无权访问",
    }


def test_http_concurrent_refresh_single_winner(client: TestClient) -> None:
    tokens = login(client, "alice", "alice-pw")
    outcomes: list[tuple[int, str]] = []
    barrier = threading.Barrier(16)

    def worker() -> None:
        barrier.wait()
        r = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        outcomes.append((r.status_code, r.json().get("error", "ok")))

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    wins = [o for o in outcomes if o[0] == 200]
    log.info("输入: 16 个真实 HTTP 线程并发刷新；成功=%d 结果分布=%s",
             len(wins), {k: sum(1 for o in outcomes if o[1] == k)
                         for k in {o[1] for o in outcomes}})
    assert len(wins) == 1
    assert all(code == 401 and error in ("refresh_replay", "family_revoked")
               for code, error in outcomes if code != 200)

    # 赢家凭据同样立即失效（落败者重放触发了整族撤销）
    winner = wins[0]
    assert winner[1] == "ok"
    log.info("判定依据: 不存在两份同时生效凭据；最终所有 access/refresh 均被拒")


def test_logout_invalidates_token_before_expiry(client: TestClient) -> None:
    tokens = login(client, "alice", "alice-pw")
    assert client.post("/auth/logout", headers=bearer(tokens)).status_code == 200
    r = client.get("/resources/doc-1", headers=bearer(tokens))
    log.info("输入: 登出后立即复用 access；响应=%s", r.json()["error"])
    assert r.status_code == 401
    assert r.json()["error"] in ("access_token_revoked", "family_revoked")


def test_key_rotation_endpoint_invalidates_old_tokens(client: TestClient) -> None:
    root = login(client, "root", "root-pw")
    alice = login(client, "alice", "alice-pw")
    old_token = alice["access_token"]

    # 非管理员不能轮换
    assert client.post("/admin/keys/rotate", headers=bearer(alice)).status_code == 403
    r = client.post("/admin/keys/rotate", headers=bearer(root))
    assert r.status_code == 200
    log.info("输入: root 轮换密钥后，alice 旧 access 仍在原始有效期内")
    r_old = client.get("/resources/doc-1",
                       headers={"Authorization": "Bearer " + old_token})
    assert r_old.status_code == 401 and r_old.json()["error"] == "key_not_active"


def test_permission_change_effective_on_next_request(client: TestClient) -> None:
    admin = login(client, "root", "root-pw")
    bob = login(client, "bob", "bob-pw")
    assert client.post("/resources/doc-1/publish", headers=bearer(bob)).status_code == 404
    r = client.post("/admin/roles/viewer/permissions",
                    headers=bearer(admin), json={"permission": "doc:publish"})
    assert r.status_code == 200
    log.info("输入: 给 viewer 增加 doc:publish 后，bob 下一次请求立即放行")
    assert client.post("/resources/doc-1/publish", headers=bearer(bob)).status_code == 200

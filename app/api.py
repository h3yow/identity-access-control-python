"""FastAPI 入口：认证端点与受保护资源。

错误映射（原因可区分）：
- 401 token_malformed / token_expired / token_revoked / refresh_token_reused / session_not_found
- 403 forbidden（已认证但无权限，不泄漏资源存在性）
- 404 resource_not_found（授权通过但资源不存在）
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .audit import AuditAction, AuditQuery
from .authz import Permission
from .errors import AuthError, DenyReason
from .service import AuthService

_STATUS = {
    DenyReason.TOKEN_MALFORMED: 401,
    DenyReason.TOKEN_EXPIRED: 401,
    DenyReason.TOKEN_REVOKED: 401,
    DenyReason.REFRESH_REUSED: 401,
    DenyReason.SESSION_NOT_FOUND: 401,
    DenyReason.SESSION_LIMIT_REACHED: 409,
    DenyReason.FORBIDDEN: 403,
    DenyReason.RESOURCE_NOT_FOUND: 404,
}


class LoginRequest(BaseModel):
    subject: str
    roles: list[str] = []
    device: str = ""


class RefreshRequest(BaseModel):
    refresh_token: str


class RolePermissionsRequest(BaseModel):
    permissions: list[str]


def create_app(service: AuthService | None = None) -> FastAPI:
    svc = service or AuthService()
    app = FastAPI(title="identity-access-control")

    # 演示用本地资源
    svc.authorizer.add_resource("doc-1", "document")
    svc.authorizer.add_resource("doc-2", "document")

    @app.exception_handler(AuthError)
    async def auth_error_handler(_: Request, exc: AuthError) -> JSONResponse:
        return JSONResponse(
            status_code=_STATUS[exc.reason],
            content={"error": exc.reason.value, "detail": exc.detail},
        )

    def bearer_token(request: Request) -> str:
        header = request.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise AuthError(DenyReason.TOKEN_MALFORMED, "缺少或非法的 Bearer 令牌")
        return token

    @app.post("/login")
    def login(body: LoginRequest) -> dict:
        pair = svc.login(body.subject, body.roles, body.device)
        return {
            "access_token": pair.access_token,
            "refresh_token": pair.refresh_token,
            "session_id": pair.session_id,
        }

    @app.post("/refresh")
    def refresh(body: RefreshRequest) -> dict:
        pair = svc.refresh(body.refresh_token)
        return {
            "access_token": pair.access_token,
            "refresh_token": pair.refresh_token,
            "session_id": pair.session_id,
        }

    @app.post("/logout")
    def logout(token: str = Depends(bearer_token)) -> dict:
        svc.logout(token)
        return {"status": "logged_out"}

    @app.get("/sessions")
    def list_sessions(token: str = Depends(bearer_token)) -> dict:
        sessions = svc.list_my_sessions(token)
        return {"sessions": [
            {
                "session_id": s.session_id,
                "status": s.status,
                "device": s.device,
                "created_at": s.created_at,
                "last_refreshed_at": s.last_refreshed_at,
            }
            for s in sessions
        ]}

    @app.post("/sessions/revoke-others")
    def revoke_others(token: str = Depends(bearer_token)) -> dict:
        revoked = svc.revoke_other_sessions(token)
        return {"status": "revoked", "revoked_session_ids": revoked}

    @app.post("/sessions/{session_id}/revoke")
    def revoke(session_id: str, token: str = Depends(bearer_token)) -> dict:
        # 自助撤销：仅能撤销自己的会话；撤销当前会话返回 403 forbidden
        svc.revoke_my_session(token, session_id)
        return {"status": "revoked", "session_id": session_id}

    @app.get("/audit")
    def query_audit(
        subject: str | None = None,
        action: str | None = None,
        start: int | None = None,
        end: int | None = None,
        offset: int = 0,
        limit: int = 50,
        token: str = Depends(bearer_token),
    ) -> dict:
        action_enum = AuditAction(action) if action is not None else None
        page = svc.query_audit(
            token,
            AuditQuery(subject=subject, action=action_enum, start=start, end=end,
                       offset=offset, limit=limit),
        )
        return {
            "total": page.total,
            "offset": page.offset,
            "limit": page.limit,
            "items": [
                {
                    "seq": e.seq,
                    "timestamp": e.timestamp,
                    "subject": e.subject,
                    "action": e.action.value,
                    "result": e.result,
                    "session_id": e.session_id,
                    "detail": e.detail,
                }
                for e in page.items
            ],
        }

    @app.post("/keys/rotate")
    def rotate_keys(token: str = Depends(bearer_token)) -> dict:
        svc.authorize(token, Permission("keys", "rotate"))
        svc.rotate_keys(token)
        return {"status": "rotated"}

    @app.put("/roles/{role}/permissions")
    def set_role_permissions(role: str, body: RolePermissionsRequest,
                             token: str = Depends(bearer_token)) -> dict:
        svc.authorize(token, Permission("role", "manage"))
        svc.set_role_permissions(token, role, {Permission.parse(p) for p in body.permissions})
        return {"status": "updated", "role": role}

    @app.get("/resources/{resource_id}")
    def read_resource(resource_id: str, token: str = Depends(bearer_token)) -> dict:
        subject = svc.authorize(token, Permission("document", "read"), resource_id)
        return {"resource_id": resource_id, "subject": subject}

    @app.get("/")
    def root() -> dict:
        return {"service": "identity-access-control"}

    return app

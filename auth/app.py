"""FastAPI 入口：登录/刷新/登出、密钥轮换、受保护资源、角色管理。

HTTP 映射约定（服务层保留精确原因）：
- 凭据缺失/格式错误/失效/被撤销 -> 401，body 中 error 为可区分原因码；
- 已认证但无权执行该操作 -> 资源类接口返回 404 且与“资源不存在”响应体一致，
  不泄漏资源是否存在；
- 刷新令牌重放（含并发落败者）-> 401 error=refresh_replay，且整族已撤销；
- 登录口令错误 -> 401 invalid_credentials（不区分用户是否存在）。
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from . import audit
from .errors import AuthError, DenyReason
from .keys import KeyManager
from .service import AuthService
from .store import LocalStore

# 原因码 -> HTTP 状态码
_STATUS_401 = {
    DenyReason.MISSING_CREDENTIAL,
    DenyReason.MALFORMED_TOKEN,
    DenyReason.UNSUPPORTED_TOKEN_TYPE,
    DenyReason.BAD_SIGNATURE,
    DenyReason.KEY_NOT_ACTIVE,
    DenyReason.TOKEN_EXPIRED,
    DenyReason.SESSION_REVOKED,
    DenyReason.FAMILY_REVOKED,
    DenyReason.ACCESS_TOKEN_REVOKED,
    DenyReason.REFRESH_REPLAY,
    DenyReason.REFRESH_UNKNOWN,
    DenyReason.INVALID_CREDENTIALS,
    DenyReason.USER_DISABLED,
}


class LoginBody(BaseModel):
    username: str
    password: str


class RefreshBody(BaseModel):
    refresh_token: str


class LogoutBody(BaseModel):
    access_token: str | None = None


class PermissionBody(BaseModel):
    permission: str


NOT_FOUND_BODY = {"error": "not_found", "error_description": "资源不存在或无权访问"}


def create_app(service: AuthService) -> FastAPI:
    app = FastAPI(title="本地身份认证与会话访问控制服务", version="0.1.0")
    app.state.service = service

    @app.exception_handler(AuthError)
    async def _auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
        status = 401 if exc.reason in _STATUS_401 else 403
        audit.audit("http_deny", path=request.url.path, reason=exc.reason.value,
                    detail=exc.detail)
        return JSONResponse(
            status_code=status,
            content={"error": exc.reason.value, "error_description": exc.detail},
        )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/auth/login")
    def login(body: LoginBody) -> dict[str, object]:
        issued = service.login(body.username, body.password)
        return {
            "access_token": issued.access_token,
            "refresh_token": issued.refresh_token,
            "token_type": "Bearer",
            "access_expires_in": issued.access_expires_in,
            "refresh_expires_in": issued.refresh_expires_in,
            "family_id": issued.family_id,
        }

    @app.post("/auth/refresh")
    def refresh(body: RefreshBody) -> dict[str, object]:
        issued = service.refresh(body.refresh_token)
        return {
            "access_token": issued.access_token,
            "refresh_token": issued.refresh_token,
            "token_type": "Bearer",
            "access_expires_in": issued.access_expires_in,
            "refresh_expires_in": issued.refresh_expires_in,
            "family_id": issued.family_id,
        }

    @app.post("/auth/logout")
    def logout(body: LogoutBody | None = None, authorization: str | None = Header(default=None)) -> dict[str, str]:
        # 优先用请求体令牌，其次 Authorization 头
        token = body.access_token if body is not None else None
        if token is None:
            if not authorization or not authorization.startswith("Bearer "):
                raise AuthError(DenyReason.MISSING_CREDENTIAL, "缺少访问令牌")
            token = authorization[len("Bearer "):]
        service.logout(token)
        return {"status": "logged_out"}

    @app.post("/admin/keys/rotate")
    def rotate_keys(authorization: str | None = Header(default=None)) -> dict[str, str]:
        # 需要 admin 操作权限
        service.guard(authorization, "admin:rotate_keys")
        kid = service.rotate_keys()
        return {"rotated_kid": kid, "effect": "此前签发的访问令牌立即失效"}

    @app.post("/admin/roles/{role}/permissions")
    def add_permission(role: str, body: PermissionBody,
                       authorization: str | None = Header(default=None)) -> JSONResponse:
        service.guard(authorization, "admin:manage_roles")
        service.add_role_permission(role, body.permission)
        return JSONResponse({"role": role, "permission": body.permission, "op": "added"})

    @app.delete("/admin/roles/{role}/permissions/{permission:path}")
    def remove_permission(role: str, permission: str,
                          authorization: str | None = Header(default=None)) -> dict[str, str]:
        service.guard(authorization, "admin:manage_roles")
        service.remove_role_permission(role, permission)
        return {"role": role, "permission": permission, "op": "removed"}

    @app.post("/admin/sessions/{family_id}/revoke")
    def revoke_session(family_id: str,
                       authorization: str | None = Header(default=None)) -> dict[str, str]:
        service.guard(authorization, "admin:revoke_session")
        service.revoke_family(family_id)
        return {"family_id": family_id, "status": "revoked"}

    # ---------------- 受保护资源（按操作粒度授权） ----------------
    RESOURCES: dict[str, dict[str, str]] = {
        "doc-1": {"owner": "alice", "content": "公开文档内容"},
    }

    def _resource_guard(authorization: str | None, operation: str):
        """鉴权失败与资源不存在返回完全相同的 404，避免资源存在性泄漏。"""
        try:
            ctx = service.guard(authorization, operation)
        except AuthError as exc:
            if exc.reason == DenyReason.FORBIDDEN_OPERATION:
                audit.audit("resource_hidden", operation=operation,
                            reason=exc.reason.value, response=404)
                return JSONResponse(status_code=404, content=NOT_FOUND_BODY)
            raise
        return ctx

    @app.get("/resources/{resource_id}")
    def read_resource(resource_id: str,
                      authorization: str | None = Header(default=None)):
        hidden = _resource_guard(authorization, "doc:read")
        if isinstance(hidden, JSONResponse):
            return hidden
        resource = RESOURCES.get(resource_id)
        # 资源不存在与越权返回完全一致
        if resource is None:
            return JSONResponse(status_code=404, content=NOT_FOUND_BODY)
        return {"id": resource_id, **resource}

    @app.post("/resources/{resource_id}/publish")
    def publish_resource(resource_id: str,
                         authorization: str | None = Header(default=None)):
        hidden = _resource_guard(authorization, "doc:publish")
        if isinstance(hidden, JSONResponse):
            return hidden
        resource = RESOURCES.get(resource_id)
        if resource is None:
            return JSONResponse(status_code=404, content=NOT_FOUND_BODY)
        return {"id": resource_id, "status": "published"}

    return app


def build_default_service() -> AuthService:
    """构造服务并播种本地演示用户/角色/权限（全部本地，无外部身份服务）。"""
    service = AuthService(LocalStore(), KeyManager())

    service.add_role_permission("viewer", "doc:read")
    service.add_role_permission("editor", "doc:read")
    service.add_role_permission("editor", "doc:publish")
    service.add_role_permission("admin", "*")

    service.create_user("alice", "alice-pw", ["editor", "viewer"])
    service.create_user("bob", "bob-pw", ["viewer"])
    service.create_user("root", "root-pw", ["admin"])
    return service

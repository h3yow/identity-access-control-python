"""基于角色的授权判定（骨架）。"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Permission:
    """细化到具体操作的权限点。"""

    resource: str   # 例如 "document"
    action: str     # 例如 "read" / "write" / "delete"

    def key(self) -> str:
        return f"{self.resource}:{self.action}"


class RoleStore:
    """角色 -> 权限集合，线程安全，修改即生效。"""

    def __init__(self) -> None:
        raise NotImplementedError

    def set_role_permissions(self, role: str, permissions: set[Permission]) -> None:
        raise NotImplementedError

    def permissions_of(self, roles: list[str]) -> set[Permission]:
        raise NotImplementedError

    def assign(self, subject: str, roles: list[str]) -> None:
        raise NotImplementedError

    def roles_of(self, subject: str) -> list[str]:
        raise NotImplementedError


class Authorizer:
    """授权判定：先认证后鉴权，未授权不泄漏资源存在性。"""

    def __init__(self, roles: RoleStore, resources: dict[str, str] | None = None) -> None:
        raise NotImplementedError

    def check(self, subject: str, permission: Permission, resource_id: str | None = None) -> None:
        """无权限抛 FORBIDDEN；有权限但资源不存在抛 RESOURCE_NOT_FOUND。"""
        raise NotImplementedError

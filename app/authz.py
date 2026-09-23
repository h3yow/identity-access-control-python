"""基于角色的授权判定。

- 权限细化到 "资源:操作" 的权限点。
- 角色权限与用户角色分配保存在本地内存，读写同一把锁，
  修改提交后下一次判定即生效（无缓存快照）。
- 判定顺序：先认证（由上层完成）-> 再鉴权；无权限时一律返回 FORBIDDEN，
  不区分资源是否存在，避免泄漏资源存在性。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from .errors import AuthError, DenyReason


@dataclass(frozen=True)
class Permission:
    """细化到具体操作的权限点。"""

    resource: str   # 例如 "document"
    action: str     # 例如 "read" / "write" / "delete"

    def key(self) -> str:
        return f"{self.resource}:{self.action}"

    @staticmethod
    def parse(text: str) -> "Permission":
        resource, sep, action = text.partition(":")
        if not sep or not resource or not action:
            raise ValueError(f"非法权限点: {text!r}")
        return Permission(resource, action)


class RoleStore:
    """角色 -> 权限集合，以及 用户 -> 角色 分配；线程安全，修改即生效。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._role_permissions: dict[str, frozenset[Permission]] = {}
        self._subject_roles: dict[str, tuple[str, ...]] = {}

    def set_role_permissions(self, role: str, permissions: set[Permission]) -> None:
        with self._lock:
            self._role_permissions[role] = frozenset(permissions)

    def permissions_of(self, roles: list[str]) -> set[Permission]:
        with self._lock:
            result: set[Permission] = set()
            for role in roles:
                result.update(self._role_permissions.get(role, ()))
            return result

    def assign(self, subject: str, roles: list[str]) -> None:
        with self._lock:
            self._subject_roles[subject] = tuple(roles)

    def roles_of(self, subject: str) -> list[str]:
        with self._lock:
            return list(self._subject_roles.get(subject, ()))


class Authorizer:
    """授权判定：先鉴权、后查资源，未授权不泄漏资源存在性。"""

    def __init__(self, roles: RoleStore, resources: dict[str, str] | None = None) -> None:
        self._roles = roles
        # resource_id -> 资源类型；用于在授权通过后再判断存在性
        self._resources: dict[str, str] = resources if resources is not None else {}
        self._lock = threading.Lock()

    def add_resource(self, resource_id: str, resource_type: str) -> None:
        with self._lock:
            self._resources[resource_id] = resource_type

    def check(self, subject: str, permission: Permission, resource_id: str | None = None) -> None:
        """无权限抛 FORBIDDEN（不泄漏存在性）；有权限但资源不存在抛 RESOURCE_NOT_FOUND。"""
        granted = self._roles.permissions_of(self._roles.roles_of(subject))
        if permission not in granted:
            raise AuthError(
                DenyReason.FORBIDDEN,
                f"subject={subject} 缺少权限 {permission.key()}",
            )
        if resource_id is not None:
            with self._lock:
                known = resource_id in self._resources
            if not known:
                raise AuthError(DenyReason.RESOURCE_NOT_FOUND, f"资源不存在: {resource_id}")

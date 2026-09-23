"""基于角色的操作级授权判定（RBAC）。

- 权限细化到“资源:操作”；
- 判定实时读取角色表，权限调整在下一次请求即生效；
- 返回结构化 Decision，记录判定依据，便于日志解释；
- 调用方（HTTP 资源层）对“无权限”与“资源不存在”返回相同 404，
  避免泄漏资源是否存在；原因差异保留在本层结果与日志中。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Decision:
    allowed: bool
    username: str
    operation: str
    matched_permissions: tuple[str, ...] = ()
    reason: str | None = None  # DenyReason.value 或 None

    def explain(self) -> str:
        if self.allowed:
            return (
                f"ALLOW user={self.username} op={self.operation} "
                f"via={list(self.matched_permissions)}"
            )
        return (
            f"DENY user={self.username} op={self.operation} "
            f"reason={self.reason} via={list(self.matched_permissions)}"
        )


def permission_matches(granted: str, required: str) -> bool:
    """支持精确匹配与通配：'doc:read'、'doc:*'、'*'。"""
    if granted == required:
        return True
    if granted == "*":
        return True
    if granted.endswith(":*"):
        return required.startswith(granted[:-1])  # 保留 ':'，要求 '资源:' 前缀
    return False

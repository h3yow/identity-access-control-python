"""认证服务门面：签发、刷新、撤销、密钥轮换、授权判定（骨架）。"""

from __future__ import annotations

from dataclasses import dataclass

from .authz import Authorizer, Permission, RoleStore
from .sessions import SessionStore
from .tokens import KeyRing, TokenCodec


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    session_id: str


class AuthService:
    """组合令牌、会话与授权，对外提供一致的操作入口。"""

    def __init__(
        self,
        access_ttl: int = 300,
        refresh_ttl: int = 3600,
        now=None,
    ) -> None:
        raise NotImplementedError

    def login(self, subject: str, roles: list[str]) -> TokenPair:
        raise NotImplementedError

    def refresh(self, refresh_token: str) -> TokenPair:
        raise NotImplementedError

    def logout(self, access_token: str) -> None:
        raise NotImplementedError

    def revoke_session(self, session_id: str) -> None:
        raise NotImplementedError

    def rotate_keys(self) -> None:
        raise NotImplementedError

    def authorize(self, access_token: str, permission: Permission, resource_id: str | None = None) -> str:
        """校验访问令牌并做授权判定，返回 subject。"""
        raise NotImplementedError

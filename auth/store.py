"""本地内存状态存储：用户/角色、会话族、刷新令牌、已签发访问令牌。

全部状态保存在进程内存，受一把可重入锁保护；授权判定每次实时读取，
角色权限调整在下一次请求即生效，不做任何权限缓存。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass
class UserRecord:
    username: str
    password_hash: str
    roles: list[str]
    enabled: bool = True


@dataclass
class SessionFamily:
    """刷新令牌族：一次登录一个族，族内刷新令牌单链轮换。"""

    family_id: str
    username: str
    revoked: bool = False
    # 当前有效的刷新令牌 id（轮换时原子替换）
    current_refresh_id: str | None = None


@dataclass
class RefreshTokenRecord:
    token_id: str
    family_id: str
    username: str
    used: bool = False
    revoked: bool = False
    issued_at: int = 0
    expires_at: int = 0


@dataclass
class AccessTokenRecord:
    jti: str
    family_id: str
    username: str
    active: bool = True  # 登出/主动撤销时置 False
    issued_at: int = 0
    expires_at: int = 0


class LocalStore:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.users: dict[str, UserRecord] = {}
        self.roles: dict[str, set[str]] = {}
        self.families: dict[str, SessionFamily] = {}
        self.refresh_tokens: dict[str, RefreshTokenRecord] = {}
        self.access_tokens: dict[str, AccessTokenRecord] = {}

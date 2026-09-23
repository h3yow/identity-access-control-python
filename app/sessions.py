"""会话与刷新令牌状态存储（骨架）。"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class SessionStatus(str, enum.Enum):
    ACTIVE = "active"
    LOGGED_OUT = "logged_out"
    REVOKED = "revoked"            # 主动撤销
    REUSED_REVOKED = "reused"      # 因刷新令牌重放被撤销


@dataclass
class RefreshRecord:
    """一枚刷新令牌的状态。"""

    token_id: str
    generation: int
    used: bool = False


@dataclass
class Session:
    """一个会话（对应一个刷新令牌族）。"""

    session_id: str
    family_id: str
    subject: str
    status: SessionStatus = SessionStatus.ACTIVE
    current_generation: int = 0
    refresh_tokens: dict[str, RefreshRecord] = field(default_factory=dict)


class SessionStore:
    """线程安全的会话存储：轮换、撤销、重放检测。"""

    def __init__(self) -> None:
        raise NotImplementedError

    def create(self, subject: str, token_id: str) -> Session:
        raise NotImplementedError

    def rotate(self, session_id: str, old_token_id: str, new_token_id: str) -> Session:
        """一次性轮换；重放时撤销整个会话族并抛 AuthError。"""
        raise NotImplementedError

    def get(self, session_id: str) -> Session | None:
        raise NotImplementedError

    def logout(self, session_id: str) -> None:
        raise NotImplementedError

    def revoke(self, session_id: str) -> None:
        raise NotImplementedError

    def revoke_all_before(self, issued_before: int, now: int) -> None:
        """密钥轮换后，使签发时间早于阈值的会话全部失效。"""
        raise NotImplementedError

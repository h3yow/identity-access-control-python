"""会话与刷新令牌状态存储。

一致性规则：
- 刷新令牌一次性轮换：rotate 在单把锁内完成"校验旧令牌 -> 标记已用 -> 登记新令牌"，
  因此同一刷新令牌的并发刷新只有一个能成功。
- 已使用（或未知）的刷新令牌再次被提交 => 判定为重放，撤销整个会话族，
  并抛出 DenyReason.REFRESH_REUSED。
- 登出 / 主动撤销 / 重放撤销后，该会话所有令牌一律拒绝。
"""

from __future__ import annotations

import enum
import threading
import uuid
from dataclasses import dataclass, field

from .errors import AuthError, DenyReason


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
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}

    def create(self, subject: str, token_id: str) -> Session:
        with self._lock:
            session = Session(
                session_id=uuid.uuid4().hex,
                family_id=uuid.uuid4().hex,
                subject=subject,
            )
            session.refresh_tokens[token_id] = RefreshRecord(token_id, generation=0)
            self._sessions[session.session_id] = session
            return session

    def _require_active(self, session: Session | None) -> Session:
        if session is None:
            raise AuthError(DenyReason.SESSION_NOT_FOUND, "会话不存在")
        if session.status is SessionStatus.REUSED_REVOKED:
            raise AuthError(DenyReason.REFRESH_REUSED, "会话族已因刷新令牌重放被撤销")
        if session.status is not SessionStatus.ACTIVE:
            raise AuthError(DenyReason.TOKEN_REVOKED, f"会话已失效: {session.status.value}")
        return session

    def rotate(self, session_id: str, old_token_id: str, new_token_id: str) -> Session:
        """一次性轮换；重放时撤销整个会话族并抛 AuthError(REFRESH_REUSED)。"""
        with self._lock:
            session = self._require_active(self._sessions.get(session_id))
            if new_token_id in session.refresh_tokens:
                # 防御：新令牌标识必须新鲜，避免覆盖"已使用"标记
                raise AuthError(DenyReason.TOKEN_MALFORMED, "新刷新令牌标识冲突")
            record = session.refresh_tokens.get(old_token_id)
            if record is None or record.used:
                # 重放（或伪造的族内令牌）：撤销整个会话族
                session.status = SessionStatus.REUSED_REVOKED
                raise AuthError(DenyReason.REFRESH_REUSED, "刷新令牌已被使用，会话族已撤销")
            record.used = True
            session.current_generation += 1
            session.refresh_tokens[new_token_id] = RefreshRecord(
                new_token_id, generation=session.current_generation
            )
            return session

    def get(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def require_active(self, session_id: str) -> Session:
        """供访问令牌校验使用：会话非 ACTIVE 时抛出可区分原因。"""
        with self._lock:
            return self._require_active(self._sessions.get(session_id))

    def logout(self, session_id: str) -> None:
        with self._lock:
            session = self._require_active(self._sessions.get(session_id))
            session.status = SessionStatus.LOGGED_OUT

    def revoke(self, session_id: str) -> None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise AuthError(DenyReason.SESSION_NOT_FOUND, "会话不存在")
            session.status = SessionStatus.REVOKED

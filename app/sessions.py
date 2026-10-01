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
import time
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
    device: str = ""
    created_at: int = 0
    last_refreshed_at: int = 0


class SessionStore:
    """线程安全的会话存储：轮换、撤销、重放检测、并发容量限制。"""

    def __init__(self, max_sessions_per_subject: int = 5, now=None) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}
        self._max_sessions_per_subject = max_sessions_per_subject
        self._now = now or (lambda: int(time.time()))

    def create(self, subject: str, token_id: str, device: str = "") -> Session:
        """在单把锁内完成"容量检查 -> 建会话"，达到上限时不创建任何状态。

        因此并发登录下：有效会话数绝不超过上限，被拒登录不会留下会话或令牌。
        """
        now = self._now()
        with self._lock:
            active = [
                s for s in self._sessions.values()
                if s.subject == subject and s.status is SessionStatus.ACTIVE
            ]
            if len(active) >= self._max_sessions_per_subject:
                raise AuthError(
                    DenyReason.SESSION_LIMIT_REACHED,
                    f"用户 {subject} 的并发会话已达上限 "
                    f"{self._max_sessions_per_subject}",
                )
            ts = now
            session = Session(
                session_id=uuid.uuid4().hex,
                family_id=uuid.uuid4().hex,
                subject=subject,
                device=device,
                created_at=ts,
                last_refreshed_at=ts,
            )
            session.refresh_tokens[token_id] = RefreshRecord(token_id, generation=0)
            self._sessions[session.session_id] = session
            return session

    def list_active(self, subject: str) -> list[Session]:
        """返回该主体当前仍有效的会话，按创建时间升序（稳定）。"""
        with self._lock:
            return sorted(
                (s for s in self._sessions.values()
                 if s.subject == subject and s.status is SessionStatus.ACTIVE),
                key=lambda s: (s.created_at, s.session_id),
            )

    def revoke_owned(self, session_id: str, subject: str) -> Session:
        """撤销属于该 subject 的有效会话。

        非属主 / 不存在一律按 SESSION_NOT_FOUND 拒绝（不泄漏他人会话是否存在）；
        非 ACTIVE 状态走 _require_active 给出可区分原因。
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.subject != subject:
                raise AuthError(DenyReason.SESSION_NOT_FOUND, "会话不存在")
            self._require_active(session)
            session.status = SessionStatus.REVOKED
            return session

    def revoke_others(self, subject: str, keep_session_id: str) -> list[str]:
        """撤销 subject 除 keep_session_id 外的全部有效会话，返回被撤销的会话标识。

        保留的当前会话不会被误撤销；当前会话不存在/非属主时抛 SESSION_NOT_FOUND。
        """
        with self._lock:
            keep = self._sessions.get(keep_session_id)
            if keep is None or keep.subject != subject:
                raise AuthError(DenyReason.SESSION_NOT_FOUND, "当前会话不存在")
            self._require_active(keep)
            revoked: list[str] = []
            for s in self._sessions.values():
                if (s.subject == subject and s.session_id != keep_session_id
                        and s.status is SessionStatus.ACTIVE):
                    s.status = SessionStatus.REVOKED
                    revoked.append(s.session_id)
            return sorted(revoked)


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
            session.last_refreshed_at = self._now()
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

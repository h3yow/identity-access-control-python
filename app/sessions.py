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
    device_label: str = ""           # 可选的设备/客户端说明
    created_at: int = 0
    last_refreshed_at: int = 0


@dataclass(frozen=True)
class SessionInfo:
    """对外暴露的会话视图（不含令牌内部状态）。"""

    session_id: str
    subject: str
    status: SessionStatus
    device_label: str
    created_at: int
    last_refreshed_at: int

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "subject": self.subject,
            "status": self.status.value,
            "device_label": self.device_label,
            "created_at": self.created_at,
            "last_refreshed_at": self.last_refreshed_at,
        }


class SessionStore:
    """线程安全的会话存储：轮换、撤销、重放检测、按主体的容量限制。"""

    DEFAULT_LIMIT = 5

    def __init__(self, max_sessions_per_subject: int = DEFAULT_LIMIT, now=None) -> None:
        if max_sessions_per_subject < 1:
            raise ValueError("max_sessions_per_subject 必须 >= 1")
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}
        self._limit = max_sessions_per_subject
        self._now = now or time.time

    def _info(self, session: Session) -> SessionInfo:
        return SessionInfo(
            session_id=session.session_id,
            subject=session.subject,
            status=session.status,
            device_label=session.device_label,
            created_at=session.created_at,
            last_refreshed_at=session.last_refreshed_at,
        )

    def create(self, subject: str, token_id: str, device_label: str = "") -> Session:
        with self._lock:
            active = sum(
                1 for s in self._sessions.values()
                if s.subject == subject and s.status is SessionStatus.ACTIVE
            )
            if active >= self._limit:
                # 容量检查与插入在同一把锁内：并发登录不可能越过上限，
                # 且此处先于任何令牌签发，拒绝不会留下半成功状态。
                raise AuthError(
                    DenyReason.SESSION_LIMIT_REACHED,
                    f"用户 {subject} 的并发会话已达上限 {self._limit}",
                )
            now = self._now()
            session = Session(
                session_id=uuid.uuid4().hex,
                family_id=uuid.uuid4().hex,
                subject=subject,
                device_label=device_label or "",
                created_at=now,
                last_refreshed_at=now,
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
            session.last_refreshed_at = self._now()
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

    # ---- 自助会话管理 --------------------------------------------------

    def list_active(self, subject: str) -> list[SessionInfo]:
        """列出某主体当前仍有效的会话，按创建时间升序（稳定顺序）。"""
        with self._lock:
            infos = [
                self._info(s) for s in self._sessions.values()
                if s.subject == subject and s.status is SessionStatus.ACTIVE
            ]
        infos.sort(key=lambda i: (i.created_at, i.session_id))
        return infos

    def revoke_owned(self, subject: str, session_id: str) -> SessionInfo:
        """撤销属于自己的单个会话。

        - 会话不存在 => SESSION_NOT_FOUND
        - 会话属于他人 => FORBIDDEN（不允许跨主体操作）
        - 已失效会话幂等处理：直接返回其当前视图。
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise AuthError(DenyReason.SESSION_NOT_FOUND, "会话不存在")
            if session.subject != subject:
                raise AuthError(DenyReason.FORBIDDEN, "无权操作他人会话")
            session.status = SessionStatus.REVOKED
            return self._info(session)

    def revoke_others(self, subject: str, keep_session_id: str) -> list[SessionInfo]:
        """撤销某主体除指定会话外的全部 *有效* 会话，返回被撤销会话视图。"""
        revoked: list[SessionInfo] = []
        with self._lock:
            for session in self._sessions.values():
                if (
                    session.subject == subject
                    and session.session_id != keep_session_id
                    and session.status is SessionStatus.ACTIVE
                ):
                    session.status = SessionStatus.REVOKED
                    revoked.append(self._info(session))
        revoked.sort(key=lambda i: (i.created_at, i.session_id))
        return revoked

    def active_count(self, subject: str) -> int:
        with self._lock:
            return sum(
                1 for s in self._sessions.values()
                if s.subject == subject and s.status is SessionStatus.ACTIVE
            )

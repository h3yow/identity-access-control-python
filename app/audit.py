"""会话安全审计：动作记录与分页查询。

记录的动作覆盖：登录（含容量拒绝）、刷新成功/拒绝、登出、单会话撤销、
批量撤销、异常刷新终止、密钥轮换、角色权限调整。
"""

from __future__ import annotations

import enum
import threading
import time
from collections import deque
from dataclasses import dataclass


class AuditAction(str, enum.Enum):
    LOGIN = "login"
    LOGIN_REJECTED = "login_rejected"
    REFRESH = "refresh"
    REFRESH_REJECTED = "refresh_rejected"
    LOGOUT = "logout"
    SESSION_REVOKE = "session_revoke"
    SESSIONS_REVOKE_OTHERS = "sessions_revoke_others"
    SESSION_TERMINATED = "session_terminated"
    KEY_ROTATE = "key_rotate"
    ROLE_PERMISSIONS_CHANGE = "role_permissions_change"


@dataclass(frozen=True)
class AuditEntry:
    """一条审计记录。"""

    seq: int
    timestamp: int
    subject: str
    action: AuditAction
    result: str
    session_id: str | None = None
    detail: str = ""


@dataclass(frozen=True)
class AuditQuery:
    """审计查询条件。"""

    subject: str | None = None
    action: AuditAction | None = None
    start: int | None = None
    end: int | None = None
    offset: int = 0
    limit: int = 50


@dataclass(frozen=True)
class AuditPage:
    """分页结果；总条数为满足过滤条件的全部记录数。"""

    items: list[AuditEntry]
    total: int
    offset: int
    limit: int


class AuditLog:
    """线程安全的本地内存审计日志，容量上限，超限丢弃最旧记录。"""

    def __init__(self, max_entries: int = 10_000, now=None) -> None:
        if max_entries < 1:
            raise ValueError("max_entries 必须 >= 1")
        self._lock = threading.Lock()
        self._entries: deque[AuditEntry] = deque()
        self._seq = 0
        self._max_entries = max_entries
        self._now = now or (lambda: int(time.time()))

    def record(self, subject: str, action: AuditAction, result: str,
               session_id: str | None = None, detail: str = "") -> AuditEntry:
        """追加一条记录。

        - 同一把锁内分配全局单调递增 seq，并发写入不会丢失或重复。
        - 超过容量上限时丢弃最旧记录（有界 deque），内存占用可预期。
        """
        with self._lock:
            self._seq += 1
            entry = AuditEntry(
                seq=self._seq,
                timestamp=self._now(),
                subject=subject,
                action=action,
                result=result,
                session_id=session_id or None,
                detail=detail,
            )
            self._entries.append(entry)
            if len(self._entries) > self._max_entries:
                self._entries.popleft()
            return entry

    def query(self, q: AuditQuery) -> AuditPage:
        """按 主体/动作/时间范围 过滤，稳定排序（时间升序，同时间按 seq 升序）。

        返回当前页与满足过滤条件的总条数；分页基于 seq 游标式切片，结果稳定。
        """
        with self._lock:
            snapshot = list(self._entries)

        matched: list[AuditEntry] = []
        for e in snapshot:
            if q.subject is not None and e.subject != q.subject:
                continue
            if q.action is not None and e.action is not q.action:
                continue
            if q.start is not None and e.timestamp < q.start:
                continue
            if q.end is not None and e.timestamp > q.end:
                continue
            matched.append(e)

        matched.sort(key=lambda e: (e.timestamp, e.seq))
        total = len(matched)
        offset = max(0, q.offset)
        limit = max(1, q.limit)
        page = matched[offset:offset + limit]
        return AuditPage(items=page, total=total, offset=offset, limit=limit)

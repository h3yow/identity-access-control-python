"""会话安全审计日志（仅本地内存）。

设计约束：
- 有界容量：超过 max_records 后丢弃最旧记录（FIFO），行为可预期、不无限占用内存。
- 并发写入不丢不重：追加与容量裁剪在单把锁内完成，每条记录带单调递增序号。
- 查询支持按主体 / 动作 / 时间范围过滤，按序号稳定排序与 offset 分页。
"""

from __future__ import annotations

import enum
import threading
import time
from collections import deque
from dataclasses import dataclass


class AuditAction(str, enum.Enum):
    """审计动作。"""

    LOGIN = "login"
    REFRESH = "refresh"
    LOGOUT = "logout"
    SESSION_REVOKE = "session_revoke"
    SESSIONS_REVOKE_OTHERS = "sessions_revoke_others"
    SESSION_TERMINATED = "session_terminated"
    KEY_ROTATE = "key_rotate"
    ROLE_PERMISSIONS_CHANGE = "role_permissions_change"


@dataclass(frozen=True)
class AuditRecord:
    """一条审计记录。"""

    seq: int
    timestamp: int
    subject: str
    action: AuditAction
    result: str
    session_id: str | None
    detail: str


@dataclass(frozen=True)
class AuditPage:
    """分页查询结果。"""

    items: list[AuditRecord]
    total: int
    offset: int
    limit: int


class AuditLog:
    """有界、线程安全的审计日志。

    容量写满后新记录仍会写入，同时丢弃最旧的记录（环形 FIFO），
    因此内存占用恒不超过 max_records 条；被丢弃的是最旧而非最新记录。
    """

    def __init__(self, max_records: int = 10_000, now=None) -> None:
        if max_records < 1:
            raise ValueError("max_records 必须 >= 1")
        self._now = now or (lambda: int(time.time()))
        self._max = max_records
        self._lock = threading.Lock()
        self._records: deque[AuditRecord] = deque(maxlen=max_records)
        self._seq = 0  # 单调递增序号，跨裁剪也不复用

    def append(self, subject: str, action: AuditAction, result: str,
               session_id: str | None = None, detail: str = "") -> AuditRecord:
        """追加一条记录；满容量时自动淘汰最旧记录。返回写入的记录。"""
        with self._lock:
            self._seq += 1
            record = AuditRecord(
                seq=self._seq,
                timestamp=self._now(),
                subject=subject,
                action=action,
                result=result,
                session_id=session_id,
                detail=detail,
            )
            # deque(maxlen=...) 在满员时原子地弹出最旧记录
            self._records.append(record)
            return record

    def query(self, *, subject: str | None = None, actions=None,
              start: int | None = None, end: int | None = None,
              offset: int = 0, limit: int = 50) -> AuditPage:
        """按条件过滤并分页。

        - 排序固定为 seq 升序（稳定）。
        - start/end 为 epoch 秒闭区间；actions 为允许的动作集合。
        - 返回过滤后的总数 total 与当前页 items。
        """
        if offset < 0:
            offset = 0
        if limit < 1:
            raise ValueError("limit 必须 >= 1")
        wanted = set(actions) if actions else None
        with self._lock:
            snapshot = list(self._records)
        filtered: list[AuditRecord] = []
        for rec in snapshot:  # snapshot 已按 seq 升序
            if subject is not None and rec.subject != subject:
                continue
            if wanted is not None and rec.action not in wanted:
                continue
            if start is not None and rec.timestamp < start:
                continue
            if end is not None and rec.timestamp > end:
                continue
            filtered.append(rec)
        page = filtered[offset:offset + limit]
        return AuditPage(items=page, total=len(filtered), offset=offset, limit=limit)

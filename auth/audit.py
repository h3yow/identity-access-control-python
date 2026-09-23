"""判定审计日志：统一记录输入摘要与判定依据，保证结果可解释。

敏感值（完整令牌、口令）只记录摘要（前 8 位 + 长度），不记录原文。
"""

from __future__ import annotations

import hashlib
import logging

logger = logging.getLogger("auth.audit")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


def token_fingerprint(token: str | None) -> str:
    if not token:
        return "<none>"
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]
    return f"len={len(token)}:sha256={digest}"


def audit(event: str, **fields: object) -> None:
    """记录一条结构化判定日志（key=value 形式）。"""
    parts = [f"event={event}"]
    for key, value in fields.items():
        parts.append(f"{key}={value!r}")
    logger.info(" ".join(parts))

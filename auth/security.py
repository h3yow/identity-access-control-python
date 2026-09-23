"""口令哈希与随机标识生成（本地演示，不依赖外部身份服务）。"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

_PBKDF2_ROUNDS = 200_000


def new_id() -> str:
    """生成密码学随机标识（会话/族/令牌/jti），32 字节 -> urlsafe 文本。"""
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")


def hash_password(password: str) -> str:
    """PBKDF2-HMAC-SHA256 加盐哈希，返回自描述字符串。

    格式：pbkdf2_sha256$<rounds>$<salt_b64>$<hash_b64>
    """
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ROUNDS)
    return "pbkdf2_sha256${}${}${}".format(
        _PBKDF2_ROUNDS,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, stored: str) -> bool:
    """恒定时间比较口令；格式无法解析时返回 False。"""
    try:
        scheme, rounds_s, salt_b64, hash_b64 = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        rounds = int(rounds_s)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
    except (ValueError, TypeError):
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return hmac.compare_digest(candidate, expected)

"""签名密钥管理（本地内存）。

规则：
- 任意时刻只有一把“当前签名密钥”，拥有唯一 kid；
- 轮换生成新密钥并立即丢弃旧密钥，旧 kid 签发的访问令牌在下一次校验时即被拒绝
  （KEY_NOT_ACTIVE），从而满足“密钥轮换后旧访问令牌在原始有效期内也必须立即失效”。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import threading

from .security import new_id


class KeyManager:
    """线程安全的单活动签名密钥管理器（HMAC-SHA256）。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._current: tuple[str, bytes] = self._generate()

    @staticmethod
    def _generate() -> tuple[str, bytes]:
        return new_id(), os.urandom(32)

    @property
    def current_kid(self) -> str:
        with self._lock:
            return self._current[0]

    def current_secret(self) -> bytes:
        with self._lock:
            return self._current[1]

    def rotate(self) -> str:
        """生成新密钥并丢弃旧密钥，返回新 kid。"""
        with self._lock:
            self._current = self._generate()
            return self._current[0]

    def sign(self, payload_b64: str) -> tuple[str, str]:
        """用当前密钥签名，返回 (kid, signature_b64url)。"""
        with self._lock:
            kid, secret = self._current
        digest = hmac.new(secret, payload_b64.encode("ascii"), hashlib.sha256).digest()
        return kid, base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    def verify(self, kid: str, signing_input: str, signature: str) -> tuple[bool, bool]:
        """返回 (kid_active, signature_ok)。

        - kid 不是当前活动密钥 -> (False, False)：旧密钥已被轮换丢弃；
        - kid 活动但签名不符 -> (True, False)。
        两者刻意分开，便于区分 KEY_NOT_ACTIVE 与 BAD_SIGNATURE。
        """
        with self._lock:
            current_kid, secret = self._current
        if kid != current_kid:
            return False, False
        try:
            provided = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        except (ValueError, TypeError):
            return True, False
        expected = hmac.new(secret, signing_input.encode("ascii"), hashlib.sha256).digest()
        return True, hmac.compare_digest(provided, expected)

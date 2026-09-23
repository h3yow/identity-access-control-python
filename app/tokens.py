"""令牌签名编解码与签名密钥轮换。

令牌格式（类 JWT，仅依赖标准库）：
    base64url(header).base64url(payload).base64url(hmac_sha256)
header 携带 kid，验签时按 kid 在密钥环中查找对应密钥。
"""

from __future__ import annotations

import base64
import enum
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass

from .errors import AuthError, DenyReason


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


class TokenType(str, enum.Enum):
    ACCESS = "access"
    REFRESH = "refresh"


@dataclass(frozen=True)
class TokenPayload:
    """令牌载荷。"""

    token_type: TokenType
    subject: str          # 用户标识
    session_id: str       # 所属会话
    family_id: str        # 刷新令牌会话族
    token_id: str         # 令牌唯一标识（jti）
    generation: int       # 刷新令牌轮换代次
    issued_at: int        # 签发时间（epoch 秒）
    expires_at: int       # 过期时间（epoch 秒）
    key_id: str           # 签名密钥标识

    def to_dict(self) -> dict:
        return {
            "typ": self.token_type.value,
            "sub": self.subject,
            "sid": self.session_id,
            "fam": self.family_id,
            "jti": self.token_id,
            "gen": self.generation,
            "iat": self.issued_at,
            "exp": self.expires_at,
            "kid": self.key_id,
        }

    @staticmethod
    def from_dict(data: dict) -> "TokenPayload":
        try:
            return TokenPayload(
                token_type=TokenType(data["typ"]),
                subject=str(data["sub"]),
                session_id=str(data["sid"]),
                family_id=str(data["fam"]),
                token_id=str(data["jti"]),
                generation=int(data["gen"]),
                issued_at=int(data["iat"]),
                expires_at=int(data["exp"]),
                key_id=str(data["kid"]),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise AuthError(DenyReason.TOKEN_MALFORMED, f"payload 字段非法: {exc}") from exc


@dataclass(frozen=True)
class KeyPair:
    """签名密钥版本。"""

    key_id: str
    secret: bytes
    activated_at: int


class KeyRing:
    """签名密钥环：rotate 后新令牌用新密钥签发，旧密钥仍可验签（由上层决定旧令牌是否继续有效）。"""

    def __init__(self, now=None) -> None:
        self._now = now or (lambda: int(time.time()))
        self._lock = threading.Lock()
        self._keys: dict[str, KeyPair] = {}
        self._retired: set[str] = set()
        self._current_id: str = ""
        self.rotate()

    def current(self) -> KeyPair:
        with self._lock:
            return self._keys[self._current_id]

    def rotate(self) -> KeyPair:
        with self._lock:
            if self._current_id:
                # 旧密钥进入退役集合：仍可验签，但签发的令牌一律视为失效
                self._retired.add(self._current_id)
            key = KeyPair(
                key_id=secrets.token_hex(8),
                secret=secrets.token_bytes(32),
                activated_at=self._now(),
            )
            self._keys[key.key_id] = key
            self._current_id = key.key_id
            return key

    def get(self, key_id: str) -> KeyPair | None:
        with self._lock:
            return self._keys.get(key_id)

    def is_retired(self, key_id: str) -> bool:
        with self._lock:
            return key_id in self._retired


class TokenCodec:
    """令牌编解码：HMAC-SHA256 签名，失败原因可区分。"""

    def __init__(self, keyring: KeyRing, now=None) -> None:
        self._keyring = keyring
        self._now = now or (lambda: int(time.time()))

    def encode(self, payload: TokenPayload) -> str:
        key = self._keyring.get(payload.key_id)
        if key is None:
            raise AuthError(DenyReason.TOKEN_MALFORMED, f"未知密钥 {payload.key_id}")
        header = _b64e(json.dumps({"alg": "HS256", "kid": payload.key_id}).encode())
        body = _b64e(json.dumps(payload.to_dict()).encode())
        sig = _b64e(hmac.new(key.secret, f"{header}.{body}".encode(), hashlib.sha256).digest())
        return f"{header}.{body}.{sig}"

    def decode(self, token: str) -> TokenPayload:
        """验签并解析；失败时抛出携带可区分 DenyReason 的 AuthError。"""
        try:
            header_b64, body_b64, sig_b64 = token.split(".")
            header = json.loads(_b64d(header_b64))
            sig = _b64d(sig_b64)
        except Exception as exc:
            raise AuthError(DenyReason.TOKEN_MALFORMED, "令牌结构无法解析") from exc

        if header.get("alg") != "HS256":
            raise AuthError(DenyReason.TOKEN_MALFORMED, "不支持的签名算法")
        key = self._keyring.get(str(header.get("kid", "")))
        if key is None:
            raise AuthError(DenyReason.TOKEN_MALFORMED, "未知签名密钥")

        expected = hmac.new(key.secret, f"{header_b64}.{body_b64}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, sig):
            raise AuthError(DenyReason.TOKEN_MALFORMED, "签名校验失败")

        try:
            payload = TokenPayload.from_dict(json.loads(_b64d(body_b64)))
        except AuthError:
            raise
        except Exception as exc:
            raise AuthError(DenyReason.TOKEN_MALFORMED, "载荷无法解析") from exc

        if payload.expires_at <= self._now():
            raise AuthError(DenyReason.TOKEN_EXPIRED, "令牌已过期")
        return payload

"""令牌签名编解码与签名密钥轮换（骨架）。"""

from __future__ import annotations

import enum
from dataclasses import dataclass


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


@dataclass(frozen=True)
class KeyPair:
    """签名密钥版本。"""

    key_id: str
    secret: bytes
    activated_at: int


class KeyRing:
    """签名密钥环：支持轮换，旧密钥仅用于验签窗口期。"""

    def __init__(self, now=None) -> None:
        raise NotImplementedError

    def current(self) -> KeyPair:
        raise NotImplementedError

    def rotate(self) -> KeyPair:
        raise NotImplementedError

    def get(self, key_id: str) -> KeyPair | None:
        raise NotImplementedError


class TokenCodec:
    """令牌编解码：HMAC 签名，验签结果可区分。"""

    def __init__(self, keyring: KeyRing, now=None) -> None:
        raise NotImplementedError

    def encode(self, payload: TokenPayload) -> str:
        raise NotImplementedError

    def decode(self, token: str) -> TokenPayload:
        """验签并解析；失败时抛出携带 DenyReason 的 AuthError。"""
        raise NotImplementedError

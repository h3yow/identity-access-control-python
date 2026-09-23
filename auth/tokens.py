"""访问令牌的紧凑序列化与解析（JWT 风格：header.payload.signature）。

刷新令牌为不透明随机串，仅存服务端，不使用本模块编码。
访问令牌 claims：sub / sid / jti / iat / exp / typ=access。
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from .errors import AuthError, DenyReason


@dataclass(frozen=True)
class AccessTokenClaims:
    sub: str
    sid: str
    jti: str
    iat: int
    exp: int


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    except (ValueError, TypeError) as exc:
        raise AuthError(DenyReason.MALFORMED_TOKEN, "base64url 解码失败") from exc


@dataclass(frozen=True)
class ParsedToken:
    kid: str
    claims: AccessTokenClaims
    signing_input: str
    signature: str


def encode_access_token(claims: AccessTokenClaims, kid: str, secret_signer) -> str:
    """编码访问令牌。secret_signer 为 KeyManager（用其当前密钥签名）。"""
    header = {"alg": "HS256", "typ": "JWT", "kid": kid}
    payload = {
        "sub": claims.sub,
        "sid": claims.sid,
        "jti": claims.jti,
        "iat": claims.iat,
        "exp": claims.exp,
        "typ": "access",
    }
    h = b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    p = b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{h}.{p}"
    _, signature = secret_signer.sign(signing_input)
    return f"{signing_input}.{signature}"


def parse_access_token(token: str) -> ParsedToken:
    """仅做结构解析（不验签、不查状态）。结构非法抛 MALFORMED_TOKEN。"""
    if not token or token.count(".") != 2:
        raise AuthError(DenyReason.MALFORMED_TOKEN, "令牌段数不为 3")
    h_b64, p_b64, signature = token.split(".")
    if not h_b64 or not p_b64 or not signature:
        raise AuthError(DenyReason.MALFORMED_TOKEN, "存在空段")
    try:
        header = json.loads(b64url_decode(h_b64))
        payload = json.loads(b64url_decode(p_b64))
    except AuthError:
        raise
    except (ValueError, UnicodeDecodeError) as exc:
        raise AuthError(DenyReason.MALFORMED_TOKEN, "header/payload 非合法 JSON") from exc

    if not isinstance(header, dict) or header.get("alg") != "HS256" or header.get("typ") != "JWT":
        raise AuthError(DenyReason.MALFORMED_TOKEN, "不支持的令牌头")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise AuthError(DenyReason.MALFORMED_TOKEN, "缺少 kid")
    if not isinstance(payload, dict) or payload.get("typ") != "access":
        raise AuthError(DenyReason.MALFORMED_TOKEN, "非访问令牌类型")
    try:
        claims = AccessTokenClaims(
            sub=str(payload["sub"]),
            sid=str(payload["sid"]),
            jti=str(payload["jti"]),
            iat=int(payload["iat"]),
            exp=int(payload["exp"]),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise AuthError(DenyReason.MALFORMED_TOKEN, f"claims 不完整: {exc}") from exc

    return ParsedToken(kid=kid, claims=claims, signing_input=f"{h_b64}.{p_b64}", signature=signature)

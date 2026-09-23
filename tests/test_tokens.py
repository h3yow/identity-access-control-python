"""访问令牌编码、解析、签名与格式错误判定测试。"""

from __future__ import annotations

import logging

import pytest

from auth.errors import AuthError, DenyReason
from auth.keys import KeyManager
from auth.tokens import (
    AccessTokenClaims,
    b64url_decode,
    b64url_encode,
    encode_access_token,
    parse_access_token,
)

log = logging.getLogger("test.tokens")


def _claims() -> AccessTokenClaims:
    return AccessTokenClaims(sub="alice", sid="sid-1", jti="jti-1", iat=100, exp=200)


def test_b64url_roundtrip() -> None:
    raw = bytes(range(256))
    encoded = b64url_encode(raw)
    assert "=" not in encoded and "+" not in encoded and "/" not in encoded
    assert b64url_decode(encoded) == raw
    log.info("input=bytes(0..255) 判定依据=b64url 无填充往返一致")


def test_encode_parse_roundtrip() -> None:
    km = KeyManager()
    token = encode_access_token(_claims(), km.current_kid, km)
    log.info("input_token_prefix=%r 判定依据=三段式解析且 claims 还原", token[:24])
    parsed = parse_access_token(token)
    assert parsed.claims == _claims()
    assert parsed.kid == km.current_kid


@pytest.mark.parametrize(
    "bad,expected_reason",
    [
        ("", DenyReason.MALFORMED_TOKEN),
        ("a.b", DenyReason.MALFORMED_TOKEN),
        ("a..c", DenyReason.MALFORMED_TOKEN),
        ("x.y.z", DenyReason.MALFORMED_TOKEN),
        ("aaa.bbb", DenyReason.MALFORMED_TOKEN),
    ],
)
def test_malformed_structure(bad: str, expected_reason: DenyReason) -> None:
    log.info("input=%r 判定依据=段数/空段/base64/json 结构校验", bad)
    with pytest.raises(AuthError) as exc:
        parse_access_token(bad)
    assert exc.value.reason == expected_reason


def test_signature_tamper_is_detectable() -> None:
    km = KeyManager()
    token = encode_access_token(_claims(), km.current_kid, km)
    head, payload, sig = token.split(".")
    # 篡改签名段
    log.info("input=篡改 signature 判定依据=HMAC 恒定时间比较不匹配")
    tampered_sig = ("A" if sig[0] != "A" else "B") + sig[1:]
    active, ok = km.verify(km.current_kid, f"{head}.{payload}", tampered_sig)
    assert active is True and ok is False
    # 篡改 payload 段
    log.info("input=篡改 payload 判定依据=签名不再覆盖新内容")
    active, ok = km.verify(km.current_kid, f"{head}.{payload[:-1]}x", sig)
    assert active is True and ok is False


def test_key_rotation_rejects_old_kid() -> None:
    km = KeyManager()
    token = encode_access_token(_claims(), km.current_kid, km)
    parsed = parse_access_token(token)
    old_kid = km.rotate()
    log.info("input=old_kid=%s 判定依据=kid 非当前活动密钥 -> KEY_NOT_ACTIVE", old_kid[:8])
    active, ok = km.verify(parsed.kid, parsed.signing_input, parsed.signature)
    assert active is False and ok is False

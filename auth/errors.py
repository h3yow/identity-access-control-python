"""认证与授权判定错误类型。

所有拒绝原因都用明确的枚举值表示，保证：
- 令牌重放、会话/族撤销、密钥失效、权限不足、格式错误等原因可区分；
- HTTP 层、服务层和测试日志对同一判定使用同一套原因编码。
"""

from __future__ import annotations

from enum import Enum


class DenyReason(str, Enum):
    """授权判定被拒绝的可区分原因。"""

    # 凭据缺失或格式无法解析
    MISSING_CREDENTIAL = "missing_credential"
    MALFORMED_TOKEN = "malformed_token"
    UNSUPPORTED_TOKEN_TYPE = "unsupported_token_type"

    # 签名 / 密钥
    BAD_SIGNATURE = "bad_signature"
    KEY_NOT_ACTIVE = "key_not_active"  # kid 存在但签名密钥已轮换（旧令牌立即失效）

    # 生命周期
    TOKEN_EXPIRED = "token_expired"
    SESSION_REVOKED = "session_revoked"
    FAMILY_REVOKED = "family_revoked"
    ACCESS_TOKEN_REVOKED = "access_token_revoked"  # 登出/主动撤销后 jti 立即失效

    # 刷新令牌专用
    REFRESH_REPLAY = "refresh_replay"  # 刷新令牌已被使用过（含并发竞争中的落败者）
    REFRESH_UNKNOWN = "refresh_unknown"

    # 登录
    INVALID_CREDENTIALS = "invalid_credentials"

    # 授权
    FORBIDDEN_OPERATION = "forbidden_operation"
    USER_DISABLED = "user_disabled"
    ROLE_UNKNOWN = "role_unknown"


class AuthError(Exception):
    """携带明确拒绝原因的认证/授权异常。"""

    def __init__(self, reason: DenyReason, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason.value}: {detail}" if detail else reason.value)

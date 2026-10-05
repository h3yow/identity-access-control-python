"""可区分的失败原因定义。"""

from __future__ import annotations

import enum


class DenyReason(str, enum.Enum):
    """认证 / 授权失败的可区分原因。"""

    TOKEN_MALFORMED = "token_malformed"            # 格式错误 / 签名无效
    TOKEN_EXPIRED = "token_expired"                # 已过期
    TOKEN_REVOKED = "token_revoked"                # 会话已撤销 / 密钥轮换后失效
    REFRESH_REUSED = "refresh_token_reused"        # 刷新令牌重放（会话族已撤销）
    SESSION_NOT_FOUND = "session_not_found"        # 会话不存在
    SESSION_LIMIT_REACHED = "session_limit_reached"  # 并发会话数达到上限
    CURRENT_SESSION_REVOKE_DENIED = "current_session_revoke_denied"  # 不允许撤销当前会话
    FORBIDDEN = "forbidden"                        # 已通过认证但无权限
    RESOURCE_NOT_FOUND = "resource_not_found"      # 资源不存在（仅授权通过后可见）


class AuthError(Exception):
    """携带可区分原因的认证/授权异常。"""

    def __init__(self, reason: DenyReason, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail or reason.value
        super().__init__(self.detail)

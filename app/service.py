"""认证服务门面：签发、刷新、撤销、密钥轮换、授权判定。

一致性要点：
- 刷新 = 验签 + 会话内一次性轮换（SessionStore 单锁保证并发只成功一次）。
- 登出 / 撤销 / 重放撤销后，访问令牌在校验时实时查询会话状态，立即失效。
- 密钥轮换记录时间阈值，轮换前签发的所有令牌一律按 TOKEN_REVOKED 拒绝，
  不依赖任何缓存，所有入口判定一致。
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass

from .authz import Authorizer, Permission, RoleStore
from .errors import AuthError, DenyReason
from .sessions import SessionStore
from .tokens import KeyRing, TokenCodec, TokenPayload, TokenType


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    session_id: str


class AuthService:
    """组合令牌、会话与授权，对外提供一致的操作入口。"""

    def __init__(
        self,
        access_ttl: int = 300,
        refresh_ttl: int = 3600,
        now=None,
    ) -> None:
        self._now = now or (lambda: int(time.time()))
        self._access_ttl = access_ttl
        self._refresh_ttl = refresh_ttl
        self.keyring = KeyRing(now=self._now)
        self.codec = TokenCodec(self.keyring, now=self._now)
        self.sessions = SessionStore()
        self.roles = RoleStore()
        self.authorizer = Authorizer(self.roles)
        self._lock = threading.Lock()
        # 密钥轮换时间阈值：早于该时间签发的令牌一律失效
        self._valid_after = 0

    # ---- 内部 helpers -------------------------------------------------

    def _mint(self, subject: str, session_id: str, family_id: str,
              generation: int, refresh_jti: str) -> TokenPair:
        now = self._now()
        kid = self.keyring.current().key_id
        access = self.codec.encode(TokenPayload(
            token_type=TokenType.ACCESS, subject=subject, session_id=session_id,
            family_id=family_id, token_id=uuid.uuid4().hex, generation=generation,
            issued_at=now, expires_at=now + self._access_ttl, key_id=kid,
        ))
        refresh = self.codec.encode(TokenPayload(
            token_type=TokenType.REFRESH, subject=subject, session_id=session_id,
            family_id=family_id, token_id=refresh_jti, generation=generation,
            issued_at=now, expires_at=now + self._refresh_ttl, key_id=kid,
        ))
        return TokenPair(access, refresh, session_id)

    def _check_rotation_cutoff(self, payload: TokenPayload) -> None:
        with self._lock:
            valid_after = self._valid_after
        if payload.issued_at < valid_after:
            raise AuthError(DenyReason.TOKEN_REVOKED, "签名密钥已轮换，令牌失效")

    # ---- 公开操作 ------------------------------------------------------

    def login(self, subject: str, roles: list[str]) -> TokenPair:
        self.roles.assign(subject, roles)
        refresh_jti = uuid.uuid4().hex
        session = self.sessions.create(subject, refresh_jti)
        return self._mint(subject, session.session_id, session.family_id, 0, refresh_jti)

    def refresh(self, refresh_token: str) -> TokenPair:
        payload = self.codec.decode(refresh_token)
        if payload.token_type is not TokenType.REFRESH:
            raise AuthError(DenyReason.TOKEN_MALFORMED, "非刷新令牌")
        self._check_rotation_cutoff(payload)
        new_jti = uuid.uuid4().hex
        # 一次性轮换：并发下只有一个调用能成功，重放会撤销整个会话族
        session = self.sessions.rotate(payload.session_id, payload.token_id, new_jti)
        return self._mint(session.subject, session.session_id, session.family_id,
                          session.current_generation, new_jti)

    def logout(self, access_token: str) -> None:
        payload = self.codec.decode(access_token)
        if payload.token_type is not TokenType.ACCESS:
            raise AuthError(DenyReason.TOKEN_MALFORMED, "非访问令牌")
        self.sessions.logout(payload.session_id)

    def revoke_session(self, session_id: str) -> None:
        self.sessions.revoke(session_id)

    def rotate_keys(self) -> None:
        self.keyring.rotate()
        with self._lock:
            self._valid_after = self._now()

    def authorize(self, access_token: str, permission: Permission,
                  resource_id: str | None = None) -> str:
        """校验访问令牌并做授权判定，返回 subject。"""
        payload = self.codec.decode(access_token)
        if payload.token_type is not TokenType.ACCESS:
            raise AuthError(DenyReason.TOKEN_MALFORMED, "非访问令牌")
        self._check_rotation_cutoff(payload)
        # 实时查询会话状态：登出/撤销/重放撤销立即生效，无缓存窗口
        session = self.sessions.require_active(payload.session_id)
        self.authorizer.check(session.subject, permission, resource_id)
        return session.subject

"""认证服务门面：签发、刷新、撤销、密钥轮换、授权判定。

一致性要点：
- 刷新 = 验签 + 会话内一次性轮换（SessionStore 单锁保证并发只成功一次）。
- 登出 / 撤销 / 重放撤销后，访问令牌在校验时实时查询会话状态，立即失效。
- 密钥轮换记录时间阈值，轮换前签发的所有令牌一律按 TOKEN_REVOKED 拒绝，
  不依赖任何缓存，所有入口判定一致。
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from .audit import AuditAction, AuditLog, AuditPage
from .authz import Authorizer, Permission, RoleStore
from .errors import AuthError, DenyReason
from .sessions import SessionInfo, SessionStore
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
        max_sessions_per_subject: int = SessionStore.DEFAULT_LIMIT,
        audit_max_records: int = 10_000,
        now=None,
    ) -> None:
        self._now = now or (lambda: int(time.time()))
        self._access_ttl = access_ttl
        self._refresh_ttl = refresh_ttl
        self.keyring = KeyRing(now=self._now)
        self.codec = TokenCodec(self.keyring, now=self._now)
        self.sessions = SessionStore(
            max_sessions_per_subject=max_sessions_per_subject, now=self._now
        )
        self.roles = RoleStore()
        self.authorizer = Authorizer(self.roles)
        self.audit = AuditLog(max_records=audit_max_records, now=self._now)

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
        # 以退役密钥集合判定，避免时钟秒级粒度造成的边界歧义
        if self.keyring.is_retired(payload.key_id):
            raise AuthError(DenyReason.TOKEN_REVOKED, "签名密钥已轮换，令牌失效")

    # ---- 公开操作 ------------------------------------------------------

    def login(self, subject: str, roles: list[str],
              device_label: str = "") -> TokenPair:
        self.roles.assign(subject, roles)
        refresh_jti = uuid.uuid4().hex
        try:
            # 容量检查与插入原子完成：达上限直接拒绝，不会签发任何令牌
            session = self.sessions.create(subject, refresh_jti, device_label)
        except AuthError as exc:
            self.audit.append(
                subject, AuditAction.LOGIN, f"denied:{exc.reason.value}",
                detail=exc.detail,
            )
            raise
        pair = self._mint(subject, session.session_id, session.family_id, 0, refresh_jti)
        self.audit.append(
            subject, AuditAction.LOGIN, "success",
            session_id=session.session_id,
            detail=device_label or "",
        )
        return pair

    def refresh(self, refresh_token: str) -> TokenPair:
        try:
            payload = self.codec.decode(refresh_token)
        except AuthError as exc:
            # 无法解析出可信主体，按 unknown 记录拒绝，保证"刷新被拒"均有迹可循
            self.audit.append(
                "unknown", AuditAction.REFRESH, f"denied:{exc.reason.value}",
                detail=exc.detail,
            )
            raise
        if payload.token_type is not TokenType.REFRESH:
            self.audit.append(
                payload.subject, AuditAction.REFRESH,
                f"denied:{DenyReason.TOKEN_MALFORMED.value}",
                session_id=payload.session_id, detail="非刷新令牌",
            )
            raise AuthError(DenyReason.TOKEN_MALFORMED, "非刷新令牌")
        try:
            self._check_rotation_cutoff(payload)
            new_jti = uuid.uuid4().hex
            # 一次性轮换：并发下只有一个调用能成功，重放会撤销整个会话族
            session = self.sessions.rotate(payload.session_id, payload.token_id, new_jti)
        except AuthError as exc:
            self.audit.append(
                payload.subject, AuditAction.REFRESH, f"denied:{exc.reason.value}",
                session_id=payload.session_id, detail=exc.detail,
            )
            if exc.reason is DenyReason.REFRESH_REUSED:
                # 异常刷新导致会话终止：单独留一条终止记录
                self.audit.append(
                    payload.subject, AuditAction.SESSION_TERMINATED,
                    DenyReason.REFRESH_REUSED.value,
                    session_id=payload.session_id, detail=exc.detail,
                )
            raise
        pair = self._mint(session.subject, session.session_id, session.family_id,
                          session.current_generation, new_jti)
        self.audit.append(
            session.subject, AuditAction.REFRESH, "success",
            session_id=session.session_id,
        )
        return pair

    def logout(self, access_token: str) -> None:
        payload = self.codec.decode(access_token)
        if payload.token_type is not TokenType.ACCESS:
            raise AuthError(DenyReason.TOKEN_MALFORMED, "非访问令牌")
        self.sessions.logout(payload.session_id)
        self.audit.append(
            payload.subject, AuditAction.LOGOUT, "success",
            session_id=payload.session_id,
        )

    def revoke_session(self, session_id: str) -> None:
        """直接按标识撤销（兼容旧入口；不做归属校验）。"""
        self.sessions.revoke(session_id)

    def list_sessions(self, subject: str) -> list[SessionInfo]:
        return self.sessions.list_active(subject)

    def revoke_other_sessions(self, subject: str, current_session_id: str) -> list[SessionInfo]:
        """撤销除当前会话外的其他有效会话；当前会话必须属于该主体且有效。"""
        self.sessions.require_active(current_session_id)
        current = self.sessions.get(current_session_id)
        if current is None or current.subject != subject:
            raise AuthError(DenyReason.FORBIDDEN, "当前会话不属于该主体")
        revoked = self.sessions.revoke_others(subject, current_session_id)
        self.audit.append(
            subject, AuditAction.SESSIONS_REVOKE_OTHERS, "success",
            session_id=current_session_id,
            detail="revoked=" + ",".join(i.session_id for i in revoked),
        )
        return revoked

    def rotate_keys(self) -> None:
        self.keyring.rotate()
        # 密钥轮换是全局动作，主体记为 system；无具体会话
        self.audit.append(
            "system", AuditAction.KEY_ROTATE, "success",
            detail=f"key_id={self.keyring.current().key_id}",
        )

    def set_role_permissions(self, role: str, permissions: set[Permission]) -> None:
        self.roles.set_role_permissions(role, permissions)
        self.audit.append(
            "system", AuditAction.ROLE_PERMISSIONS_CHANGE, "success",
            detail=f"role={role};permissions="
                   + ",".join(sorted(p.key() for p in permissions)),
        )

    def query_audit(self, requester_subject: str, *,
                    subject: str | None = None, actions=None,
                    start: int | None = None, end: int | None = None,
                    offset: int = 0, limit: int = 50) -> AuditPage:
        """审计查询：普通用户只能查自己；具备 audit:read 可查全部并带过滤条件。"""
        granted = Permission("audit", "read") in self.roles.permissions_of(
            self.roles.roles_of(requester_subject)
        )
        if not granted:
            if subject is not None and subject != requester_subject:
                raise AuthError(DenyReason.FORBIDDEN, "只能查询自己的审计记录")
            subject = requester_subject
        return self.audit.query(
            subject=subject, actions=actions, start=start, end=end,
            offset=offset, limit=limit,
        )

    def active_session(self, access_token: str) -> tuple[str, str]:
        """校验访问令牌与会话状态，返回 (subject, session_id)。"""
        payload = self.codec.decode(access_token)
        if payload.token_type is not TokenType.ACCESS:
            raise AuthError(DenyReason.TOKEN_MALFORMED, "非访问令牌")
        self._check_rotation_cutoff(payload)
        session = self.sessions.require_active(payload.session_id)
        return session.subject, session.session_id

    def revoke_owned_session(self, subject: str, session_id: str,
                             current_session_id: str | None = None) -> SessionInfo:
        """自助撤销：归属校验 + 审计，返回被撤销会话视图。

        当前会话（发起请求会话）不允许通过此入口撤销：先于任何状态变更
        明确拒绝，被拒绝的请求不留下任何副作用。
        """
        if current_session_id is not None and session_id == current_session_id:
            exc = AuthError(
                DenyReason.CURRENT_SESSION_REVOKE,
                "不允许撤销当前会话；如需退出请使用登出",
            )
            self.audit.append(
                subject, AuditAction.SESSION_REVOKE,
                f"denied:{exc.reason.value}",
                session_id=session_id, detail=exc.detail,
            )
            raise exc
        info = self.sessions.revoke_owned(subject, session_id)
        self.audit.append(
            subject, AuditAction.SESSION_REVOKE, "success",
            session_id=session_id, detail=f"status={info.status.value}",
        )
        return info

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

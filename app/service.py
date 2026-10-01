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

from .audit import AuditAction, AuditEntry, AuditLog, AuditPage, AuditQuery
from .authz import Authorizer, Permission, RoleStore
from .errors import AuthError, DenyReason
from .sessions import Session, SessionStatus, SessionStore
from .tokens import KeyRing, TokenCodec, TokenPayload, TokenType


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    session_id: str


@dataclass(frozen=True)
class SessionInfo:
    """会话自助管理视图。"""

    session_id: str
    status: str
    device: str
    created_at: int
    last_refreshed_at: int


class AuthService:
    """组合令牌、会话与授权，对外提供一致的操作入口。"""

    def __init__(
        self,
        access_ttl: int = 300,
        refresh_ttl: int = 3600,
        max_sessions_per_subject: int = 5,
        audit_max_entries: int = 10_000,
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
        self.audit = AuditLog(max_entries=audit_max_entries, now=self._now)

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

    def _authenticate(self, access_token: str) -> tuple[TokenPayload, Session]:
        """解码访问令牌、密钥截止判定并实时确认会话仍有效。"""
        payload = self.codec.decode(access_token)
        if payload.token_type is not TokenType.ACCESS:
            raise AuthError(DenyReason.TOKEN_MALFORMED, "非访问令牌")
        self._check_rotation_cutoff(payload)
        session = self.sessions.require_active(payload.session_id)
        return payload, session

    # ---- 公开操作 ------------------------------------------------------

    def login(self, subject: str, roles: list[str], device: str = "") -> TokenPair:
        refresh_jti = uuid.uuid4().hex
        # 容量门槛在前：被拒时不会创建会话，也不会签发任何令牌（无半成功状态）
        try:
            session = self.sessions.create(subject, refresh_jti, device)
        except AuthError as exc:
            self.audit.record(
                subject, AuditAction.LOGIN_REJECTED, exc.reason.value,
                detail=exc.detail,
            )
            raise
        self.roles.assign(subject, roles)
        pair = self._mint(subject, session.session_id, session.family_id, 0, refresh_jti)
        self.audit.record(
            subject, AuditAction.LOGIN, "ok", session_id=session.session_id,
            detail=device,
        )
        return pair

    def refresh(self, refresh_token: str) -> TokenPair:
        try:
            payload = self.codec.decode(refresh_token)
        except AuthError as exc:
            self.audit.record(
                "<unknown>", AuditAction.REFRESH_REJECTED, exc.reason.value,
                detail=exc.detail,
            )
            raise
        if payload.token_type is not TokenType.REFRESH:
            self.audit.record(
                payload.subject, AuditAction.REFRESH_REJECTED,
                DenyReason.TOKEN_MALFORMED.value,
                session_id=payload.session_id, detail="非刷新令牌",
            )
            raise AuthError(DenyReason.TOKEN_MALFORMED, "非刷新令牌")
        try:
            self._check_rotation_cutoff(payload)
        except AuthError as exc:
            self.audit.record(
                payload.subject, AuditAction.REFRESH_REJECTED, exc.reason.value,
                session_id=payload.session_id, detail=exc.detail,
            )
            raise
        new_jti = uuid.uuid4().hex
        # 一次性轮换：并发下只有一个调用能成功，重放会撤销整个会话族
        try:
            session = self.sessions.rotate(payload.session_id, payload.token_id, new_jti)
        except AuthError as exc:
            self.audit.record(
                payload.subject, AuditAction.REFRESH_REJECTED, exc.reason.value,
                session_id=payload.session_id, detail=exc.detail,
            )
            if exc.reason is DenyReason.REFRESH_REUSED:
                # 会话因异常刷新（重放/并发双提交）而终止
                self.audit.record(
                    payload.subject, AuditAction.SESSION_TERMINATED, exc.reason.value,
                    session_id=payload.session_id, detail=exc.detail,
                )
            raise
        pair = self._mint(session.subject, session.session_id, session.family_id,
                          session.current_generation, new_jti)
        self.audit.record(
            session.subject, AuditAction.REFRESH, "ok",
            session_id=session.session_id,
        )
        return pair

    def logout(self, access_token: str) -> None:
        payload, _ = self._authenticate(access_token)
        self.sessions.logout(payload.session_id)
        self.audit.record(
            payload.subject, AuditAction.LOGOUT, "ok",
            session_id=payload.session_id,
        )

    def revoke_session(self, session_id: str) -> None:
        self.sessions.revoke(session_id)

    def list_my_sessions(self, access_token: str) -> list[SessionInfo]:
        _, session = self._authenticate(access_token)
        return [
            SessionInfo(
                session_id=s.session_id,
                status=s.status.value,
                device=s.device,
                created_at=s.created_at,
                last_refreshed_at=s.last_refreshed_at,
            )
            for s in self.sessions.list_active(session.subject)
        ]

    def revoke_my_session(self, access_token: str, session_id: str) -> None:
        """用户撤销自己的某个会话；撤销当前会话被拒绝（当前会话不能被误撤销）。"""
        _, current = self._authenticate(access_token)
        if session_id == current.session_id:
            raise AuthError(
                DenyReason.FORBIDDEN,
                "不能撤销当前会话，请使用登出",
            )
        self.sessions.revoke_owned(session_id, current.subject)
        self.audit.record(
            current.subject, AuditAction.SESSION_REVOKE, "ok",
            session_id=session_id,
        )

    def revoke_other_sessions(self, access_token: str) -> list[str]:
        """撤销调用者除当前会话外的全部其他会话，返回被撤销的会话标识。"""
        _, current = self._authenticate(access_token)
        revoked = self.sessions.revoke_others(current.subject, current.session_id)
        self.audit.record(
            current.subject, AuditAction.SESSIONS_REVOKE_OTHERS, "ok",
            session_id=current.session_id,
            detail=f"revoked={len(revoked)}",
        )
        return revoked

    def query_audit(self, access_token: str, query: AuditQuery) -> AuditPage:
        """审计查询：普通用户强制只能查自己；具备 session:manage 可查全部并按条件过滤。"""
        _, session = self._authenticate(access_token)
        subject = session.subject
        granted = self.roles.permissions_of(self.roles.roles_of(subject))
        can_view_all = Permission("session", "manage") in granted
        scoped = AuditQuery(
            subject=subject if not can_view_all else query.subject,
            action=query.action,
            start=query.start,
            end=query.end,
            offset=query.offset,
            limit=query.limit,
        )
        return self.audit.query(scoped)

    def rotate_keys(self, access_token: str | None = None) -> None:
        subject = "<system>"
        if access_token is not None:
            payload, _ = self._authenticate(access_token)
            subject = payload.subject
        self.keyring.rotate()
        self.audit.record(subject, AuditAction.KEY_ROTATE, "ok")

    def set_role_permissions(self, access_token: str, role: str,
                             permissions: set[Permission]) -> None:
        """角色权限调整：需 role:manage（由入口鉴权），调整写入审计且即时生效。"""
        payload, _ = self._authenticate(access_token)
        self.roles.set_role_permissions(role, permissions)
        self.audit.record(
            payload.subject, AuditAction.ROLE_PERMISSIONS_CHANGE, "ok",
            detail=f"role={role};permissions="
                   + ",".join(sorted(p.key() for p in permissions)),
        )

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

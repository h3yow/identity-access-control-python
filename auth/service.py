"""认证服务：登录、刷新（一次性轮换+族撤销）、登出、撤销、密钥轮换、令牌校验与授权。

并发一致性：
- 刷新在 store 单锁内原子完成“读刷新令牌 -> 判定 -> 置 used / 替换族当前令牌”，
  同一刷新令牌并发刷新只有一个成功；任何重放（含落败者重试）撤销整族，
  拒绝原因为 refresh_replay；
- 访问令牌的 jti 存活集合与会话/族撤销标志在同一存储下实时判定，无缓存，
  登出/主动撤销/密钥轮换后旧令牌在所有入口判定一致立即失效。
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from . import audit
from .errors import AuthError, DenyReason
from .keys import KeyManager
from .policy import Decision, permission_matches
from .security import hash_password, new_id, verify_password
from .store import (
    AccessTokenRecord,
    LocalStore,
    RefreshTokenRecord,
    SessionFamily,
    UserRecord,
)
from .tokens import (
    AccessTokenClaims,
    encode_access_token,
    parse_access_token,
)


@dataclass(frozen=True)
class IssuedTokens:
    access_token: str
    refresh_token: str
    access_expires_in: int
    refresh_expires_in: int
    family_id: str


@dataclass(frozen=True)
class AccessContext:
    """校验通过的访问令牌上下文。"""

    claims: AccessTokenClaims
    username: str


class AuthService:
    DEFAULT_ACCESS_TTL = 900       # 15 分钟
    DEFAULT_REFRESH_TTL = 604800  # 7 天

    def __init__(
        self,
        store: LocalStore,
        keys: KeyManager,
        access_ttl: int = DEFAULT_ACCESS_TTL,
        refresh_ttl: int = DEFAULT_REFRESH_TTL,
        clock=time.time,
    ) -> None:
        self.store = store
        self.keys = keys
        self.access_ttl = access_ttl
        self.refresh_ttl = refresh_ttl
        self._clock = clock

    def _now(self) -> int:
        return int(self._clock())

    # ------------------------------------------------------------------ 用户/角色
    def create_user(self, username: str, password: str, roles: list[str]) -> None:
        with self.store.lock:
            self.store.users[username] = UserRecord(
                username=username,
                password_hash=hash_password(password),
                roles=list(roles),
            )
        audit.audit("user_created", username=username, roles=roles)

    def set_user_enabled(self, username: str, enabled: bool) -> None:
        with self.store.lock:
            user = self.store.users.get(username)
            if user is None:
                raise AuthError(DenyReason.REFRESH_UNKNOWN, f"用户不存在: {username}")
            user.enabled = enabled
        audit.audit("user_enabled_changed", username=username, enabled=enabled)

    def add_role_permission(self, role: str, permission: str) -> None:
        with self.store.lock:
            self.store.roles.setdefault(role, set()).add(permission)
        audit.audit("role_permission_added", role=role, permission=permission)

    def remove_role_permission(self, role: str, permission: str) -> None:
        with self.store.lock:
            perms = self.store.roles.get(role)
            if perms is not None:
                perms.discard(permission)
        audit.audit("role_permission_removed", role=role, permission=permission)

    # ------------------------------------------------------------------ 签发
    def _issue_tokens_locked(self, family_id: str, username: str) -> IssuedTokens:
        """调用方必须持有 store.lock。创建一对新的访问/刷新令牌并登记。"""
        now = self._now()
        family = self.store.families[family_id]

        access_id = new_id()
        claims = AccessTokenClaims(
            sub=username,
            sid=family_id,
            jti=access_id,
            iat=now,
            exp=now + self.access_ttl,
        )
        access_token = encode_access_token(claims, self.keys.current_kid, self.keys)
        self.store.access_tokens[access_id] = AccessTokenRecord(
            jti=access_id,
            family_id=family_id,
            username=username,
            active=True,
            issued_at=now,
            expires_at=now + self.access_ttl,
        )

        refresh_id = new_id()
        refresh_token = refresh_id  # 不透明令牌：其值即存储键
        self.store.refresh_tokens[refresh_id] = RefreshTokenRecord(
            token_id=refresh_id,
            family_id=family_id,
            username=username,
            used=False,
            revoked=False,
            issued_at=now,
            expires_at=now + self.refresh_ttl,
        )
        family.current_refresh_id = refresh_id

        return IssuedTokens(
            access_token=access_token,
            refresh_token=refresh_token,
            access_expires_in=self.access_ttl,
            refresh_expires_in=self.refresh_ttl,
            family_id=family_id,
        )

    # ------------------------------------------------------------------ 登录
    def login(self, username: str, password: str) -> IssuedTokens:
        # 统一错误信息：不区分“用户不存在”与“口令错误”，避免账户枚举
        with self.store.lock:
            user = self.store.users.get(username)
            valid = user is not None and verify_password(password, user.password_hash)
            if not valid:
                audit.audit("login_denied", username=username,
                            reason=DenyReason.INVALID_CREDENTIALS.value)
                raise AuthError(DenyReason.INVALID_CREDENTIALS, "用户名或口令错误")
            if not user.enabled:
                audit.audit("login_denied", username=username,
                            reason=DenyReason.USER_DISABLED.value)
                raise AuthError(DenyReason.USER_DISABLED, "账户已禁用")

            family_id = new_id()
            self.store.families[family_id] = SessionFamily(
                family_id=family_id, username=username
            )
            issued = self._issue_tokens_locked(family_id, username)

        audit.audit("login_ok", username=username, family_id=family_id,
                    access_jti=issued.access_token.split(".")[1][:10])
        return issued

    # ------------------------------------------------------------------ 刷新
    def _revoke_family_locked(self, family_id: str) -> None:
        """调用方必须持有 store.lock：撤销族及其全部刷新/访问凭据。"""
        family = self.store.families.get(family_id)
        if family is None:
            return
        family.revoked = True
        family.current_refresh_id = None
        for rt in self.store.refresh_tokens.values():
            if rt.family_id == family_id:
                rt.revoked = True
        for at in self.store.access_tokens.values():
            if at.family_id == family_id and at.active:
                at.active = False

    def refresh(self, refresh_token: str) -> IssuedTokens:
        """一次性轮换刷新令牌。

        判定顺序（全部在 store 单锁内原子完成）：
        1. 令牌不认识            -> refresh_unknown
        2. 已使用 / 已撤销       -> refresh_replay，并撤销整个族（重放攻击处置）
        3. 所属族已撤销          -> family_revoked
        4. 已过期               -> token_expired，并撤销整个族
        5. 否则成功：旧令牌置 used，原子换发新对
        """
        with self.store.lock:
            record = self.store.refresh_tokens.get(refresh_token)
            if record is None:
                audit.audit("refresh_denied",
                            token=audit.token_fingerprint(refresh_token),
                            reason=DenyReason.REFRESH_UNKNOWN.value)
                raise AuthError(DenyReason.REFRESH_UNKNOWN, "刷新令牌不存在")

            if record.used or record.revoked:
                # 重放：包括并发刷新中的落败者。撤销整族，任何凭据都不再有效。
                self._revoke_family_locked(record.family_id)
                audit.audit("refresh_replay", family_id=record.family_id,
                            token=audit.token_fingerprint(refresh_token),
                            action="family_revoked")
                raise AuthError(
                    DenyReason.REFRESH_REPLAY,
                    "刷新令牌已被使用，整个会话族已被撤销",
                )

            family = self.store.families.get(record.family_id)
            if family is None or family.revoked:
                audit.audit("refresh_denied", family_id=record.family_id,
                            reason=DenyReason.FAMILY_REVOKED.value)
                raise AuthError(DenyReason.FAMILY_REVOKED, "会话族已撤销")

            now = self._now()
            if record.expires_at <= now:
                self._revoke_family_locked(record.family_id)
                audit.audit("refresh_denied", family_id=record.family_id,
                            reason=DenyReason.TOKEN_EXPIRED.value)
                raise AuthError(DenyReason.TOKEN_EXPIRED, "刷新令牌已过期")

            # 原子轮换：先置 used，再签发新对并替换族当前令牌
            record.used = True
            record.revoked = False
            issued = self._issue_tokens_locked(record.family_id, record.username)
            audit.audit("refresh_ok", family_id=record.family_id,
                        username=record.username)
            return issued

    # ------------------------------------------------------------------ 登出/撤销/轮换
    def logout(self, access_token: str) -> None:
        """登出：校验令牌后撤销整个会话族（访问令牌与刷新令牌全部立即失效）。"""
        with self.store.lock:
            # 即使令牌已过期，只要结构可解析且能定位族，也执行撤销
            try:
                parsed = parse_access_token(access_token)
            except AuthError:
                raise
            family_id = parsed.claims.sid
            if family_id not in self.store.families:
                raise AuthError(DenyReason.SESSION_REVOKED, "会话不存在或已结束")
            self._revoke_family_locked(family_id)
        audit.audit("logout_ok", family_id=family_id)

    def revoke_family(self, family_id: str) -> None:
        """管理员主动撤销会话族；族不存在视为幂等成功。"""
        with self.store.lock:
            existed = family_id in self.store.families
            self._revoke_family_locked(family_id)
        audit.audit("family_revoked_admin", family_id=family_id, existed=existed)

    def rotate_keys(self) -> str:
        """签名密钥轮换：旧 kid 立即被丢弃，旧访问令牌下次校验即 KEY_NOT_ACTIVE。"""
        new_kid = self.keys.rotate()
        audit.audit("key_rotated", new_kid=new_kid[:8],
                    effect="旧访问令牌立即失效")
        return new_kid

    # ------------------------------------------------------------------ 校验
    def authenticate(self, authorization_header: str | None) -> AccessContext:
        """解析并校验 Authorization: Bearer <token>，失败抛 AuthError。"""
        if not authorization_header:
            audit.audit("access_denied", reason=DenyReason.MISSING_CREDENTIAL.value)
            raise AuthError(DenyReason.MISSING_CREDENTIAL, "缺少 Authorization 头")

        parts = authorization_header.split(" ", 1)
        if len(parts) != 2 or parts[0] != "Bearer" or not parts[1].strip():
            audit.audit("access_denied",
                        reason=DenyReason.MALFORMED_TOKEN.value,
                        header=authorization_header[:16])
            raise AuthError(DenyReason.MALFORMED_TOKEN, "期望 'Bearer <token>'")
        token = parts[1].strip()

        parsed = parse_access_token(token)  # 结构错误 -> MALFORMED_TOKEN

        # 密钥与签名优先：轮换后旧 kid 立刻不被认可
        kid_active, sig_ok = self.keys.verify(
            parsed.kid, parsed.signing_input, parsed.signature
        )
        if not kid_active:
            audit.audit("access_denied", jti=parsed.claims.jti[:8],
                        reason=DenyReason.KEY_NOT_ACTIVE.value)
            raise AuthError(DenyReason.KEY_NOT_ACTIVE, "签名密钥已轮换，令牌立即失效")
        if not sig_ok:
            audit.audit("access_denied", jti=parsed.claims.jti[:8],
                        reason=DenyReason.BAD_SIGNATURE.value)
            raise AuthError(DenyReason.BAD_SIGNATURE, "签名不匹配")

        now = self._now()
        with self.store.lock:
            if parsed.claims.exp <= now:
                audit.audit("access_denied", jti=parsed.claims.jti[:8],
                            reason=DenyReason.TOKEN_EXPIRED.value)
                raise AuthError(DenyReason.TOKEN_EXPIRED, "访问令牌已过期")

            at = self.store.access_tokens.get(parsed.claims.jti)
            if at is None or not at.active:
                # 登出 / 主动撤销后 jti 立即失效，判定结果全局一致、无缓存
                audit.audit("access_denied", jti=parsed.claims.jti[:8],
                            reason=DenyReason.ACCESS_TOKEN_REVOKED.value)
                raise AuthError(DenyReason.ACCESS_TOKEN_REVOKED,
                                "访问令牌已被撤销")

            family = self.store.families.get(parsed.claims.sid)
            if family is None or family.revoked:
                audit.audit("access_denied", jti=parsed.claims.jti[:8],
                            family_id=parsed.claims.sid[:8],
                            reason=DenyReason.FAMILY_REVOKED.value)
                raise AuthError(DenyReason.FAMILY_REVOKED, "会话族已撤销")

            user = self.store.users.get(parsed.claims.sub)
            if user is None or not user.enabled:
                audit.audit("access_denied", username=parsed.claims.sub,
                            reason=DenyReason.USER_DISABLED.value)
                raise AuthError(DenyReason.USER_DISABLED, "账户已禁用")

            ctx = AccessContext(claims=parsed.claims, username=parsed.claims.sub)
        return ctx

    # ------------------------------------------------------------------ 授权
    def authorize(self, ctx: AccessContext, operation: str) -> Decision:
        """操作级授权判定，实时读取角色权限（无缓存，调整下一次请求即生效）。"""
        with self.store.lock:
            user = self.store.users[ctx.username]
            granted: list[str] = []
            for role in user.roles:
                perms = self.store.roles.get(role)
                if perms is None:
                    continue
                granted.extend(sorted(perms))
        matched = tuple(p for p in granted if permission_matches(p, operation))
        if matched:
            decision = Decision(allowed=True, username=ctx.username,
                                operation=operation, matched_permissions=matched)
        else:
            decision = Decision(allowed=False, username=ctx.username,
                                operation=operation,
                                reason=DenyReason.FORBIDDEN_OPERATION.value)
        audit.audit("authorize", input_user=ctx.username, input_op=operation,
                    decision=decision.explain())
        return decision

    def guard(self, authorization_header: str | None, operation: str) -> AccessContext:
        """authenticate + authorize 组合，供受保护入口调用。"""
        ctx = self.authenticate(authorization_header)
        decision = self.authorize(ctx, operation)
        if not decision.allowed:
            raise AuthError(DenyReason.FORBIDDEN_OPERATION,
                            f"无权执行操作 {operation}")
        return ctx

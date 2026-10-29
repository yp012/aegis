"""Authentication workflows: login, refresh, logout.

Redis layout (all keys prefixed ``aegis:``):

- ``blacklist:<jti>``             revoked access token, TTL = its remaining lifetime
- ``rt:<jti>``                     hash {user_id, state=active|used} for each refresh token
- ``rt-user:<user_id>``            set of the user's *active* refresh-token jtis
- ``revoked-before:<user_id>``     epoch second; access tokens issued at or before it are dead
- ``mfa-pending-used:<jti>``       an mfa_pending token that has already been exchanged

Refresh tokens rotate on every use: the presented token is atomically marked ``used`` and a
new one is issued. Presenting a ``used`` token again means two parties hold it, so the whole
family is revoked (every active refresh token plus every access token issued so far).
"""

import hmac
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from redis import Redis
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.redis import key
from app.core.security import (
    IssuedToken,
    TokenError,
    TokenType,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    password_needs_rehash,
    seconds_until_expiry,
    subject_id,
    verify_dummy_password,
    verify_password,
)
from app.models.user import User
from app.services import mfa_service

MAX_FAILED_LOGINS = 5
LOCKOUT_DURATION = timedelta(minutes=15)

_CONSUME_REFRESH_LUA = """
local data = redis.call('HMGET', KEYS[1], 'state', 'user_id')
if not data[1] then
    return {'missing', ''}
end
if data[1] ~= 'active' then
    return {data[1], data[2]}
end
redis.call('HSET', KEYS[1], 'state', 'used')
redis.call('SREM', KEYS[2], ARGV[1])
return {'ok', data[2]}
"""

_REVOKE_ALL_LUA = """
local jtis = redis.call('SMEMBERS', KEYS[1])
for _, jti in ipairs(jtis) do
    redis.call('DEL', ARGV[1] .. jti)
end
redis.call('DEL', KEYS[1])
redis.call('SET', KEYS[2], ARGV[2], 'EX', tonumber(ARGV[3]))
return #jtis
"""


class AuthenticationError(Exception):
    """Any authentication failure. Callers must answer with one generic message."""


@dataclass(frozen=True, slots=True)
class IssuedSession:
    access: IssuedToken
    refresh: IssuedToken


def normalize_email(email: str) -> str:
    return email.strip().lower()


# --- Account lockout ----------------------------------------------------------------------


def is_locked(user: User, now: datetime) -> bool:
    return user.locked_until is not None and user.locked_until > now


def record_failed_login(user: User, now: datetime) -> None:
    """Count a failure; the 5th consecutive one locks the account for 15 minutes."""
    user.failed_login_count += 1
    if user.failed_login_count >= MAX_FAILED_LOGINS:
        user.locked_until = now + LOCKOUT_DURATION
        user.failed_login_count = 0


def record_successful_login(user: User) -> None:
    user.failed_login_count = 0
    user.locked_until = None


def authenticate(db: Session, email: str, password: str) -> User:
    """Verify email + password, enforcing lockout. Commits the attempt's outcome.

    Every path performs exactly one Argon2 verification, so response time does not reveal
    whether the account exists, is locked, or is inactive. For MFA-enabled users the failure
    counter is only reset once the second factor succeeds.
    """
    now = datetime.now(UTC)
    # Row lock serialises concurrent attempts so the failure counter cannot be raced past 5.
    user = db.scalar(select(User).where(User.email == normalize_email(email)).with_for_update())
    if user is None:
        verify_dummy_password(password)
        raise AuthenticationError

    password_ok = verify_password(user.password_hash, password)
    if is_locked(user, now) or not user.is_active:
        db.rollback()
        raise AuthenticationError
    if not password_ok:
        record_failed_login(user, now)
        db.commit()
        raise AuthenticationError

    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    if not user.mfa_enabled:
        record_successful_login(user)
    db.commit()
    return user


def complete_mfa_login(db: Session, redis: Redis, mfa_token: str, code: str) -> User:
    """Exchange a valid, unused mfa_pending token plus a fresh TOTP code for the user."""
    try:
        claims = decode_token(mfa_token, TokenType.MFA_PENDING)
    except TokenError as exc:
        raise AuthenticationError from exc
    used_key = key("mfa-pending-used", claims["jti"])
    if redis.exists(used_key):
        raise AuthenticationError

    now = datetime.now(UTC)
    user = db.scalar(select(User).where(User.id == subject_id(claims)).with_for_update())
    if user is None or not user.is_active or not user.mfa_enabled or is_locked(user, now):
        db.rollback()
        raise AuthenticationError
    if not mfa_service.verify_totp(redis, user, code):
        # Wrong second factors count toward the same lockout as wrong passwords.
        record_failed_login(user, now)
        db.commit()
        raise AuthenticationError
    # Single use: a concurrent exchange of the same pending token loses here.
    if not redis.set(used_key, "1", nx=True, ex=max(1, seconds_until_expiry(claims))):
        db.rollback()
        raise AuthenticationError
    record_successful_login(user)
    db.commit()
    return user


# --- Sessions and refresh-token rotation ---------------------------------------------------


def issue_session(redis: Redis, user: User) -> IssuedSession:
    access = create_access_token(user)
    refresh = create_refresh_token(user.id)
    _store_refresh_token(redis, user.id, refresh)
    return IssuedSession(access=access, refresh=refresh)


def _store_refresh_token(redis: Redis, user_id: uuid.UUID, refresh: IssuedToken) -> None:
    token_key = key("rt", refresh.jti)
    family_key = key("rt-user", str(user_id))
    lifetime = int(timedelta(days=get_settings().refresh_token_days).total_seconds())
    pipe = redis.pipeline(transaction=True)
    pipe.hset(token_key, mapping={"user_id": str(user_id), "state": "active"})
    pipe.expireat(token_key, refresh.expires_at)
    pipe.sadd(family_key, refresh.jti)
    pipe.expire(family_key, lifetime)
    pipe.execute()


def rotate_refresh_token(redis: Redis, token: str) -> uuid.UUID:
    """Consume a refresh token and return its user id; detect and punish reuse."""
    try:
        claims = decode_token(token, TokenType.REFRESH)
    except TokenError as exc:
        raise AuthenticationError from exc
    user_id = subject_id(claims)
    state, stored_user = redis.eval(
        _CONSUME_REFRESH_LUA,
        2,
        key("rt", claims["jti"]),
        key("rt-user", str(user_id)),
        claims["jti"],
    )
    if state == "used":
        revoke_all_sessions(redis, user_id)
        raise AuthenticationError
    if state != "ok" or not hmac.compare_digest(str(stored_user), str(user_id)):
        raise AuthenticationError
    return user_id


def revoke_all_sessions(redis: Redis, user_id: uuid.UUID) -> int:
    """Revoke every refresh token of the user and every access token issued until now."""
    access_lifetime = int(timedelta(minutes=get_settings().access_token_minutes).total_seconds())
    revoked: int = redis.eval(
        _REVOKE_ALL_LUA,
        2,
        key("rt-user", str(user_id)),
        key("revoked-before", str(user_id)),
        key("rt", ""),
        str(int(datetime.now(UTC).timestamp())),
        # Outlive any access token that could still be valid.
        str(access_lifetime + 60),
    )
    return revoked


def revoke_refresh_token(redis: Redis, token: str, user_id: uuid.UUID) -> None:
    """Best-effort revocation of the caller's own refresh token (logout)."""
    try:
        claims = decode_token(token, TokenType.REFRESH)
    except TokenError:
        return
    if not hmac.compare_digest(claims["sub"], str(user_id)):
        return
    pipe = redis.pipeline(transaction=True)
    pipe.delete(key("rt", claims["jti"]))
    pipe.srem(key("rt-user", str(user_id)), claims["jti"])
    pipe.execute()


# --- Access-token revocation ----------------------------------------------------------------


def blacklist_access_token(redis: Redis, claims: dict[str, Any]) -> None:
    ttl = seconds_until_expiry(claims)
    if ttl > 0:
        redis.set(key("blacklist", claims["jti"]), "1", ex=ttl)


def is_access_token_revoked(redis: Redis, claims: dict[str, Any]) -> bool:
    pipe = redis.pipeline(transaction=False)
    pipe.exists(key("blacklist", claims["jti"]))
    pipe.get(key("revoked-before", claims["sub"]))
    blacklisted, revoked_before = pipe.execute()
    if blacklisted:
        return True
    return revoked_before is not None and int(claims["iat"]) <= int(revoked_before)

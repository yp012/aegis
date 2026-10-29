"""Password hashing and token issuance/verification.

Passwords are hashed with Argon2id. Tokens are HMAC-signed JWTs whose algorithm is pinned to
``settings.jwt_algorithm``; ``none`` and every other algorithm are rejected. Each token
carries a ``type`` claim (access, refresh or mfa_pending) that is checked on every decode,
so one kind of token can never be used where another is expected.
"""

import enum
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import get_settings
from app.models.user import User

JWT_ISSUER = "aegis"
JWT_AUDIENCE = "aegis-api"
MFA_PENDING_TOKEN_MINUTES = 5

# argon2-cffi defaults to Argon2id with the RFC 9106 "low memory" profile (t=3, m=64 MiB, p=4).
_hasher = PasswordHasher()


class TokenType(enum.StrEnum):
    ACCESS = "access"
    REFRESH = "refresh"
    MFA_PENDING = "mfa_pending"


class TokenError(Exception):
    """Raised for any token that is malformed, forged, expired or of the wrong type."""


@dataclass(frozen=True, slots=True)
class IssuedToken:
    token: str
    jti: str
    expires_at: datetime

    @property
    def expires_in(self) -> int:
        """Whole seconds until expiry (never negative)."""
        return max(0, int((self.expires_at - datetime.now(UTC)).total_seconds()))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Return True if ``password`` matches ``password_hash``. Never raises on bad input."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


@lru_cache
def _dummy_hash() -> str:
    return _hasher.hash(secrets.token_urlsafe(32))


def verify_dummy_password(password: str) -> None:
    """Spend the same Argon2 work as a real check, for unknown accounts (timing equalisation)."""
    verify_password(_dummy_hash(), password)


def _encode(
    subject: str, token_type: TokenType, lifetime: timedelta, extra: dict[str, Any] | None = None
) -> IssuedToken:
    settings = get_settings()
    now = datetime.now(UTC)
    expires_at = now + lifetime
    jti = uuid.uuid4().hex
    claims: dict[str, Any] = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "sub": subject,
        "jti": jti,
        "type": token_type.value,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    if extra:
        claims.update(extra)
    token = jwt.encode(
        claims, settings.jwt_secret.get_secret_value(), algorithm=settings.jwt_algorithm
    )
    return IssuedToken(token=token, jti=jti, expires_at=expires_at)


def create_access_token(user: User) -> IssuedToken:
    settings = get_settings()
    return _encode(
        str(user.id),
        TokenType.ACCESS,
        timedelta(minutes=settings.access_token_minutes),
        {"role": user.role.value, "clearance": user.clearance.name},
    )


def create_refresh_token(user_id: uuid.UUID) -> IssuedToken:
    settings = get_settings()
    return _encode(str(user_id), TokenType.REFRESH, timedelta(days=settings.refresh_token_days))


def create_mfa_pending_token(user_id: uuid.UUID) -> IssuedToken:
    return _encode(
        str(user_id), TokenType.MFA_PENDING, timedelta(minutes=MFA_PENDING_TOKEN_MINUTES)
    )


def decode_token(token: str, expected_type: TokenType) -> dict[str, Any]:
    """Verify signature, algorithm, issuer, audience, expiry and type; return the claims."""
    settings = get_settings()
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            settings.jwt_secret.get_secret_value(),
            # Pinned: PyJWT rejects any header ``alg`` not in this list, including "none".
            algorithms=[settings.jwt_algorithm],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub", "jti", "type"]},
        )
    except jwt.PyJWTError as exc:
        raise TokenError("invalid token") from exc

    token_type = claims.get("type")
    if not isinstance(token_type, str) or not hmac.compare_digest(
        token_type.encode(), expected_type.value.encode()
    ):
        raise TokenError("unexpected token type")
    if not isinstance(claims.get("jti"), str) or not isinstance(claims.get("sub"), str):
        raise TokenError("malformed token claims")
    try:
        uuid.UUID(claims["sub"])
    except ValueError as exc:
        raise TokenError("malformed subject") from exc
    return claims


def subject_id(claims: dict[str, Any]) -> uuid.UUID:
    return uuid.UUID(claims["sub"])


def seconds_until_expiry(claims: dict[str, Any]) -> int:
    return max(0, int(claims["exp"]) - int(datetime.now(UTC).timestamp()))

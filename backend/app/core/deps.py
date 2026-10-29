"""FastAPI dependency providers (auth, roles, DB sessions).

Authorization decisions use the *current database row* (role, clearance, is_active), not the
claims embedded in the token, so a demotion or deactivation takes effect on the next request
rather than when the access token expires.
"""

from collections.abc import Callable
from typing import Annotated, Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from redis import Redis
from sqlalchemy.orm import Session

from app.core.redis import get_redis
from app.core.security import TokenError, TokenType, decode_token, subject_id
from app.db.session import get_db
from app.models.enums import Clearance, Role
from app.models.user import User
from app.services import auth_service

bearer_scheme = HTTPBearer(auto_error=False)

DbSession = Annotated[Session, Depends(get_db)]
RedisClient = Annotated[Redis, Depends(get_redis)]
BearerCredentials = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)]


def unauthorized() -> HTTPException:
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_access_claims(credentials: BearerCredentials, redis: RedisClient) -> dict[str, Any]:
    """Validated, non-revoked access-token claims. Fails closed if Redis is unreachable."""
    if credentials is None:
        raise unauthorized()
    try:
        claims = decode_token(credentials.credentials, TokenType.ACCESS)
    except TokenError:
        raise unauthorized() from None
    if auth_service.is_access_token_revoked(redis, claims):
        raise unauthorized()
    return claims


AccessClaims = Annotated[dict[str, Any], Depends(get_access_claims)]


def get_current_user(claims: AccessClaims, db: DbSession) -> User:
    user = db.get(User, subject_id(claims))
    if user is None or not user.is_active:
        raise unauthorized()
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_roles(*roles: Role) -> Callable[[User], User]:
    """Dependency factory: the caller must hold one of ``roles``."""
    if not roles:
        raise ValueError("require_roles needs at least one role")
    allowed = frozenset(roles)

    def dependency(user: CurrentUser) -> User:
        if user.role not in allowed:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient privileges")
        return user

    return dependency


def require_clearance(min_level: Clearance) -> Callable[[User], User]:
    """Dependency factory: the caller's clearance must meet or exceed ``min_level``."""
    if not isinstance(min_level, Clearance):
        raise TypeError("min_level must be a Clearance")

    def dependency(user: CurrentUser) -> User:
        if not user.clearance.satisfies(min_level):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient clearance")
        return user

    return dependency

"""API v1 routes: auth.

The access token is returned in the JSON body. The refresh token is only ever set as an
``HttpOnly; SameSite=Strict`` cookie scoped to the auth path, so page scripts cannot read it
and the browser sends it nowhere else. Failures use one generic message per endpoint so
responses do not reveal whether an account exists, is locked or is disabled.
"""

from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, HTTPException, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.core.config import get_settings
from app.core.deps import (
    AccessClaims,
    BearerCredentials,
    CurrentUser,
    DbSession,
    RedisClient,
    get_access_claims,
    get_current_user,
)
from app.core.rate_limit import auth_rate_limit
from app.core.security import create_mfa_pending_token, hash_password
from app.models.enums import Role
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    MfaChallengeResponse,
    MfaCodeRequest,
    MfaLoginRequest,
    MfaSetupResponse,
    MfaStatusResponse,
    RegisterRequest,
    TokenResponse,
)
from app.schemas.user import UserRead
from app.services import auth_service, mfa_service
from app.services.auth_service import AuthenticationError, IssuedSession

router = APIRouter(prefix="/auth", tags=["auth"])

REFRESH_COOKIE = "aegis_refresh"
INVALID_CREDENTIALS = "Invalid credentials"
INVALID_SESSION = "Invalid or expired session"
# Arbitrary constant key for pg_advisory_xact_lock; serialises the "first user" check.
_BOOTSTRAP_LOCK_ID = 0x41E615

RateLimited = [Depends(auth_rate_limit)]
RefreshCookie = Annotated[str | None, Cookie(alias=REFRESH_COOKIE)]


def _cookie_path() -> str:
    return f"{get_settings().api_v1_prefix}/auth"


def _set_refresh_cookie(response: Response, session: IssuedSession) -> None:
    response.set_cookie(
        REFRESH_COOKIE,
        session.refresh.token,
        max_age=session.refresh.expires_in,
        path=_cookie_path(),
        secure=get_settings().cookie_secure,
        httponly=True,
        samesite="strict",
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        REFRESH_COOKIE,
        path=_cookie_path(),
        secure=get_settings().cookie_secure,
        httponly=True,
        samesite="strict",
    )


def _token_response(response: Response, session: IssuedSession) -> TokenResponse:
    _set_refresh_cookie(response, session)
    return TokenResponse(access_token=session.access.token, expires_in=session.access.expires_in)


def _invalid_credentials() -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, INVALID_CREDENTIALS)


@router.post(
    "/register",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=RateLimited,
)
def register(
    payload: RegisterRequest,
    db: DbSession,
    redis: RedisClient,
    credentials: BearerCredentials,
) -> User:
    """Create a user. Open only while no user exists (the bootstrap Admin); Admin-only after."""
    db.execute(select(func.pg_advisory_xact_lock(_BOOTSTRAP_LOCK_ID)))
    bootstrap = db.scalar(select(func.count()).select_from(User)) == 0
    if not bootstrap:
        actor = get_current_user(get_access_claims(credentials, redis), db)
        if actor.role != Role.Admin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient privileges")

    email = auth_service.normalize_email(payload.email)
    if db.scalar(select(User.id).where(User.email == email)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
    user = User(
        email=email,
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        role=Role.Admin if bootstrap else payload.role,
        clearance=payload.clearance,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered") from None
    db.refresh(user)
    return user


@router.post(
    "/login",
    response_model=TokenResponse | MfaChallengeResponse,
    dependencies=RateLimited,
)
def login(
    payload: LoginRequest, response: Response, db: DbSession, redis: RedisClient
) -> TokenResponse | MfaChallengeResponse:
    try:
        user = auth_service.authenticate(db, payload.email, payload.password)
    except AuthenticationError:
        raise _invalid_credentials() from None
    if user.mfa_enabled:
        pending = create_mfa_pending_token(user.id)
        return MfaChallengeResponse(mfa_token=pending.token, expires_in=pending.expires_in)
    return _token_response(response, auth_service.issue_session(redis, user))


@router.post("/mfa/login", response_model=TokenResponse, dependencies=RateLimited)
def mfa_login(
    payload: MfaLoginRequest, response: Response, db: DbSession, redis: RedisClient
) -> TokenResponse:
    try:
        user = auth_service.complete_mfa_login(db, redis, payload.mfa_token, payload.code)
    except AuthenticationError:
        raise _invalid_credentials() from None
    return _token_response(response, auth_service.issue_session(redis, user))


@router.post("/mfa/setup", response_model=MfaSetupResponse, dependencies=RateLimited)
def mfa_setup(user: CurrentUser, db: DbSession) -> MfaSetupResponse:
    try:
        setup = mfa_service.begin_setup(db, user)
    except mfa_service.MfaStateError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
    return MfaSetupResponse(
        otpauth_uri=setup.otpauth_uri, qr_code_png_base64=setup.qr_code_png_base64
    )


@router.post("/mfa/verify-setup", response_model=MfaStatusResponse, dependencies=RateLimited)
def mfa_verify_setup(
    payload: MfaCodeRequest, user: CurrentUser, db: DbSession, redis: RedisClient
) -> MfaStatusResponse:
    try:
        confirmed = mfa_service.confirm_setup(db, redis, user, payload.code)
    except mfa_service.MfaStateError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
    if not confirmed:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid code")
    return MfaStatusResponse(mfa_enabled=True)


@router.post("/refresh", response_model=TokenResponse, dependencies=RateLimited)
def refresh(
    response: Response, db: DbSession, redis: RedisClient, refresh_token: RefreshCookie = None
) -> TokenResponse | JSONResponse:
    try:
        if not refresh_token:
            raise AuthenticationError
        user_id = auth_service.rotate_refresh_token(redis, refresh_token)
        user = db.get(User, user_id)
        if user is None or not user.is_active:
            auth_service.revoke_all_sessions(redis, user_id)
            raise AuthenticationError
    except AuthenticationError:
        failure = JSONResponse({"detail": INVALID_SESSION}, status.HTTP_401_UNAUTHORIZED)
        _clear_refresh_cookie(failure)
        return failure
    return _token_response(response, auth_service.issue_session(redis, user))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    claims: AccessClaims, user: CurrentUser, redis: RedisClient, refresh_token: RefreshCookie = None
) -> Response:
    auth_service.blacklist_access_token(redis, claims)
    if refresh_token:
        auth_service.revoke_refresh_token(redis, refresh_token, user.id)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    _clear_refresh_cookie(response)
    return response


@router.get("/me", response_model=UserRead)
def me(user: CurrentUser) -> User:
    return user

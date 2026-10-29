"""Unit tests (fakeredis, no database): lockout rules, refresh rotation and reuse detection,
access-token blacklisting, and TOTP replay protection."""

import base64
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pyotp
import pytest
from redis import Redis
from sqlalchemy.orm import Session

from app.core.redis import key
from app.core.security import TokenType, create_access_token, create_refresh_token, decode_token
from app.models.enums import Clearance, Role
from app.models.user import User
from app.services import auth_service, mfa_service
from app.services.auth_service import AuthenticationError


def _user(**overrides: object) -> User:
    fields: dict[str, object] = {
        "id": uuid.uuid4(),
        "email": "bob@example.com",
        "full_name": "Bob",
        "password_hash": "unused",
        "role": Role.Personnel,
        "clearance": Clearance.Reliability,
        "is_active": True,
        "mfa_enabled": False,
        "failed_login_count": 0,
        "locked_until": None,
    }
    fields.update(overrides)
    return User(**fields)


# --- Lockout -----------------------------------------------------------------------------------


def test_email_normalisation() -> None:
    assert auth_service.normalize_email("  Alice@Example.COM ") == "alice@example.com"


def test_fifth_failure_locks_for_fifteen_minutes() -> None:
    user = _user()
    now = datetime.now(UTC)
    for _ in range(4):
        auth_service.record_failed_login(user, now)
        assert not auth_service.is_locked(user, now)
    auth_service.record_failed_login(user, now)
    assert user.locked_until == now + timedelta(minutes=15)
    assert auth_service.is_locked(user, now + timedelta(minutes=14, seconds=59))
    assert not auth_service.is_locked(user, now + timedelta(minutes=15))
    # The counter restarts so the next lock needs another five failures.
    assert user.failed_login_count == 0


def test_success_resets_counter_and_lock() -> None:
    user = _user(failed_login_count=3, locked_until=datetime.now(UTC) - timedelta(minutes=1))
    auth_service.record_successful_login(user)
    assert user.failed_login_count == 0
    assert user.locked_until is None


# --- Refresh rotation --------------------------------------------------------------------------


def test_rotation_consumes_token_once(fake_redis: Redis) -> None:
    user = _user()
    session = auth_service.issue_session(fake_redis, user)
    assert auth_service.rotate_refresh_token(fake_redis, session.refresh.token) == user.id
    assert fake_redis.hget(key("rt", session.refresh.jti), "state") == "used"
    assert not fake_redis.sismember(key("rt-user", str(user.id)), session.refresh.jti)


def test_refresh_ttl_matches_token_lifetime(fake_redis: Redis) -> None:
    session = auth_service.issue_session(fake_redis, _user())
    ttl = fake_redis.ttl(key("rt", session.refresh.jti))
    assert 7 * 24 * 3600 - 5 <= int(ttl) <= 7 * 24 * 3600


def test_reuse_revokes_whole_family(fake_redis: Redis) -> None:
    user = _user()
    first = auth_service.issue_session(fake_redis, user)
    other_device = auth_service.issue_session(fake_redis, user)
    auth_service.rotate_refresh_token(fake_redis, first.refresh.token)
    rotated = auth_service.issue_session(fake_redis, user)

    with pytest.raises(AuthenticationError):
        auth_service.rotate_refresh_token(fake_redis, first.refresh.token)

    # Every refresh token in the family is gone, including the freshly rotated one.
    for token in (rotated.refresh.token, other_device.refresh.token):
        with pytest.raises(AuthenticationError):
            auth_service.rotate_refresh_token(fake_redis, token)
    assert fake_redis.scard(key("rt-user", str(user.id))) == 0
    # Access tokens issued before the theft was detected are dead too.
    for session in (first, other_device, rotated):
        claims = decode_token(session.access.token, TokenType.ACCESS)
        assert auth_service.is_access_token_revoked(fake_redis, claims)


def test_reuse_does_not_affect_other_users(fake_redis: Redis) -> None:
    victim, bystander = _user(), _user()
    stolen = auth_service.issue_session(fake_redis, victim)
    safe = auth_service.issue_session(fake_redis, bystander)
    auth_service.rotate_refresh_token(fake_redis, stolen.refresh.token)
    with pytest.raises(AuthenticationError):
        auth_service.rotate_refresh_token(fake_redis, stolen.refresh.token)
    assert auth_service.rotate_refresh_token(fake_redis, safe.refresh.token) == bystander.id


def test_unknown_refresh_token_rejected(fake_redis: Redis) -> None:
    # Validly signed, but never stored server-side.
    with pytest.raises(AuthenticationError):
        auth_service.rotate_refresh_token(fake_redis, create_refresh_token(uuid.uuid4()).token)


def test_access_token_cannot_be_used_as_refresh(fake_redis: Redis) -> None:
    session = auth_service.issue_session(fake_redis, _user())
    with pytest.raises(AuthenticationError):
        auth_service.rotate_refresh_token(fake_redis, session.access.token)


def test_refresh_token_bound_to_its_user(fake_redis: Redis) -> None:
    user = _user()
    session = auth_service.issue_session(fake_redis, user)
    # Simulate a stored record that names a different user than the token's subject.
    fake_redis.hset(key("rt", session.refresh.jti), "user_id", str(uuid.uuid4()))
    with pytest.raises(AuthenticationError):
        auth_service.rotate_refresh_token(fake_redis, session.refresh.token)


def test_logout_revokes_own_refresh_token_only(fake_redis: Redis) -> None:
    user = _user()
    session = auth_service.issue_session(fake_redis, user)
    auth_service.revoke_refresh_token(fake_redis, session.refresh.token, uuid.uuid4())
    assert fake_redis.exists(key("rt", session.refresh.jti))
    auth_service.revoke_refresh_token(fake_redis, session.refresh.token, user.id)
    assert not fake_redis.exists(key("rt", session.refresh.jti))
    with pytest.raises(AuthenticationError):
        auth_service.rotate_refresh_token(fake_redis, session.refresh.token)


def test_revoke_ignores_garbage(fake_redis: Redis) -> None:
    auth_service.revoke_refresh_token(fake_redis, "garbage", uuid.uuid4())


# --- Access blacklist ----------------------------------------------------------------------


def test_blacklist_ttl_is_remaining_lifetime(fake_redis: Redis) -> None:
    claims = decode_token(create_access_token(_user()).token, TokenType.ACCESS)
    assert not auth_service.is_access_token_revoked(fake_redis, claims)
    auth_service.blacklist_access_token(fake_redis, claims)
    assert auth_service.is_access_token_revoked(fake_redis, claims)
    ttl = int(fake_redis.ttl(key("blacklist", claims["jti"])))
    assert 590 <= ttl <= 600


def test_blacklisting_expired_claims_is_a_no_op(fake_redis: Redis) -> None:
    claims = {"jti": "x", "exp": int(datetime.now(UTC).timestamp()) - 1}
    auth_service.blacklist_access_token(fake_redis, claims)
    assert not fake_redis.exists(key("blacklist", "x"))


# --- TOTP ------------------------------------------------------------------------------------


@pytest.fixture
def mfa_user() -> tuple[User, pyotp.TOTP]:
    secret = pyotp.random_base32()
    user = _user(mfa_secret_encrypted=mfa_service.encrypt_secret(secret), mfa_enabled=True)
    return user, pyotp.TOTP(secret)


def test_secret_is_encrypted_at_rest(mfa_user: tuple[User, pyotp.TOTP]) -> None:
    user, totp = mfa_user
    assert user.mfa_secret_encrypted is not None
    assert totp.secret not in user.mfa_secret_encrypted
    assert mfa_service.decrypt_secret(user.mfa_secret_encrypted) == totp.secret


def test_totp_accepts_current_code_once(
    fake_redis: Redis, mfa_user: tuple[User, pyotp.TOTP]
) -> None:
    user, totp = mfa_user
    code = totp.now()
    assert mfa_service.verify_totp(fake_redis, user, code)
    assert not mfa_service.verify_totp(fake_redis, user, code), "replay must be rejected"
    ttl = int(fake_redis.ttl(key("totp-used", str(user.id), code)))
    assert 85 <= ttl <= 90


def test_totp_replay_is_per_user(fake_redis: Redis) -> None:
    secret = pyotp.random_base32()
    alice = _user(mfa_secret_encrypted=mfa_service.encrypt_secret(secret))
    bob = _user(mfa_secret_encrypted=mfa_service.encrypt_secret(secret))
    code = pyotp.TOTP(secret).now()
    assert mfa_service.verify_totp(fake_redis, alice, code)
    assert mfa_service.verify_totp(fake_redis, bob, code)


def test_totp_valid_window_is_one_step(
    fake_redis: Redis, mfa_user: tuple[User, pyotp.TOTP]
) -> None:
    user, totp = mfa_user
    now = datetime.now(UTC)
    assert mfa_service.verify_totp(fake_redis, user, totp.at(now - timedelta(seconds=30)))
    assert mfa_service.verify_totp(fake_redis, user, totp.at(now + timedelta(seconds=30)))
    assert not mfa_service.verify_totp(fake_redis, user, totp.at(now - timedelta(seconds=90)))
    assert not mfa_service.verify_totp(fake_redis, user, totp.at(now + timedelta(seconds=90)))


@pytest.mark.parametrize("code", ["", "12345", "1234567", "abcdef", "12 456"])
def test_malformed_codes_rejected(
    fake_redis: Redis, mfa_user: tuple[User, pyotp.TOTP], code: str
) -> None:
    assert not mfa_service.verify_totp(fake_redis, mfa_user[0], code)


def test_undecryptable_secret_rejected(fake_redis: Redis) -> None:
    user = _user(mfa_secret_encrypted="not-a-fernet-token")
    assert not mfa_service.verify_totp(fake_redis, user, "123456")


def test_setup_flow_enables_mfa(fake_redis: Redis) -> None:
    db = MagicMock(spec=Session)
    user = _user()
    setup = mfa_service.begin_setup(db, user)
    assert setup.otpauth_uri.startswith("otpauth://totp/Aegis:bob%40example.com?secret=")
    assert base64.b64decode(setup.qr_code_png_base64).startswith(b"\x89PNG\r\n\x1a\n")
    assert user.mfa_secret_encrypted is not None
    assert not user.mfa_enabled

    secret = mfa_service.decrypt_secret(user.mfa_secret_encrypted)
    assert f"secret={secret}" in setup.otpauth_uri
    current = pyotp.TOTP(secret).now()
    wrong = f"{(int(current) + 1) % 1_000_000:06d}"
    assert not mfa_service.confirm_setup(db, fake_redis, user, wrong)
    assert not user.mfa_enabled
    assert mfa_service.confirm_setup(db, fake_redis, user, current)
    assert user.mfa_enabled
    with pytest.raises(mfa_service.MfaStateError):
        mfa_service.begin_setup(db, user)
    with pytest.raises(mfa_service.MfaStateError):
        mfa_service.confirm_setup(db, fake_redis, user, "123456")


def test_confirm_requires_started_setup(fake_redis: Redis) -> None:
    with pytest.raises(mfa_service.MfaStateError, match="not been started"):
        mfa_service.confirm_setup(MagicMock(spec=Session), fake_redis, _user(), "123456")

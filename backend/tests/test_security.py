"""Unit tests: Argon2id hashing and JWT issuance/validation."""

import base64
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest

from app.core.config import get_settings
from app.core.security import (
    JWT_AUDIENCE,
    JWT_ISSUER,
    TokenError,
    TokenType,
    create_access_token,
    create_mfa_pending_token,
    create_refresh_token,
    decode_token,
    hash_password,
    password_needs_rehash,
    verify_dummy_password,
    verify_password,
)
from app.models.enums import Clearance, Role
from app.models.user import User


def _user() -> User:
    return User(
        id=uuid.uuid4(),
        email="alice@example.com",
        full_name="Alice",
        password_hash="unused",
        role=Role.SecurityOfficer,
        clearance=Clearance.Secret_Level_II,
        is_active=True,
    )


def _b64(data: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def _claims(**overrides: Any) -> dict[str, Any]:
    now = int(datetime.now(UTC).timestamp())
    claims: dict[str, Any] = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "sub": str(uuid.uuid4()),
        "jti": uuid.uuid4().hex,
        "type": "access",
        "iat": now,
        "nbf": now,
        "exp": now + 600,
    }
    claims.update(overrides)
    return claims


def _sign(claims: dict[str, Any], algorithm: str = "HS256", secret: str | None = None) -> str:
    key = secret or get_settings().jwt_secret.get_secret_value()
    return jwt.encode(claims, key, algorithm=algorithm)


# --- Passwords -----------------------------------------------------------------------------


def test_password_hash_is_argon2id_and_verifies() -> None:
    hashed = hash_password("correct horse battery staple")
    assert hashed.startswith("$argon2id$")
    assert verify_password(hashed, "correct horse battery staple")
    assert not verify_password(hashed, "wrong password")
    assert not password_needs_rehash(hashed)


def test_password_hash_is_salted() -> None:
    assert hash_password("same-password") != hash_password("same-password")


@pytest.mark.parametrize("bad_hash", ["", "not-a-hash", "$argon2id$v=19$garbage"])
def test_verify_password_never_raises_on_bad_hash(bad_hash: str) -> None:
    assert verify_password(bad_hash, "anything") is False


def test_dummy_verify_runs_without_error() -> None:
    verify_dummy_password("whatever")


# --- Tokens: happy path ----------------------------------------------------------------------


def test_access_token_claims() -> None:
    user = _user()
    issued = create_access_token(user)
    claims = decode_token(issued.token, TokenType.ACCESS)
    assert claims["sub"] == str(user.id)
    assert claims["role"] == "SecurityOfficer"
    assert claims["clearance"] == "Secret_Level_II"
    assert claims["jti"] == issued.jti
    assert claims["type"] == "access"
    assert claims["exp"] - claims["iat"] == 10 * 60
    assert 590 <= issued.expires_in <= 600


def test_refresh_token_claims() -> None:
    user_id = uuid.uuid4()
    issued = create_refresh_token(user_id)
    claims = decode_token(issued.token, TokenType.REFRESH)
    assert claims["type"] == "refresh"
    assert claims["jti"] == issued.jti
    assert claims["sub"] == str(user_id)
    assert claims["exp"] - claims["iat"] == 7 * 24 * 3600
    assert "role" not in claims


def test_mfa_pending_token_lifetime() -> None:
    claims = decode_token(create_mfa_pending_token(uuid.uuid4()).token, TokenType.MFA_PENDING)
    assert claims["exp"] - claims["iat"] == 5 * 60


def test_jtis_are_unique() -> None:
    user = _user()
    assert create_access_token(user).jti != create_access_token(user).jti


# --- Tokens: rejection -----------------------------------------------------------------------


def test_alg_none_rejected() -> None:
    unsigned = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(_claims())}."
    with pytest.raises(TokenError):
        decode_token(unsigned, TokenType.ACCESS)


def test_alg_none_via_pyjwt_rejected() -> None:
    token = jwt.encode(_claims(), "", algorithm="none")
    with pytest.raises(TokenError):
        decode_token(token, TokenType.ACCESS)


@pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning")
def test_other_hmac_algorithm_rejected() -> None:
    # Correct secret, but HS512 is not the pinned algorithm.
    with pytest.raises(TokenError):
        decode_token(_sign(_claims(), algorithm="HS512"), TokenType.ACCESS)


def test_expired_token_rejected() -> None:
    past = int((datetime.now(UTC) - timedelta(hours=1)).timestamp())
    token = _sign(_claims(iat=past - 600, nbf=past - 600, exp=past))
    with pytest.raises(TokenError):
        decode_token(token, TokenType.ACCESS)


def test_not_yet_valid_token_rejected() -> None:
    future = int((datetime.now(UTC) + timedelta(hours=1)).timestamp())
    with pytest.raises(TokenError):
        decode_token(_sign(_claims(nbf=future)), TokenType.ACCESS)


def test_tampered_payload_rejected() -> None:
    token = create_access_token(_user()).token
    header, _, signature = token.split(".")
    forged_payload = _b64(_claims(role="Admin", clearance="Top_Secret"))
    with pytest.raises(TokenError):
        decode_token(f"{header}.{forged_payload}.{signature}", TokenType.ACCESS)


def test_tampered_signature_rejected() -> None:
    token = create_access_token(_user()).token
    flipped = token[:-2] + ("AA" if token[-2:] != "AA" else "BB")
    with pytest.raises(TokenError):
        decode_token(flipped, TokenType.ACCESS)


def test_wrong_secret_rejected() -> None:
    token = _sign(_claims(), secret="another-secret-that-is-long-enough-1234567890")
    with pytest.raises(TokenError):
        decode_token(token, TokenType.ACCESS)


@pytest.mark.parametrize(
    ("token_type", "expected"),
    [
        ("refresh", TokenType.ACCESS),
        ("mfa_pending", TokenType.ACCESS),
        ("access", TokenType.REFRESH),
        ("access", TokenType.MFA_PENDING),
    ],
)
def test_wrong_token_type_rejected(token_type: str, expected: TokenType) -> None:
    with pytest.raises(TokenError, match="type"):
        decode_token(_sign(_claims(type=token_type)), expected)


@pytest.mark.parametrize("missing", ["exp", "jti", "type", "sub", "iss", "aud", "iat"])
def test_missing_required_claim_rejected(missing: str) -> None:
    claims = _claims()
    del claims[missing]
    with pytest.raises(TokenError):
        decode_token(_sign(claims), TokenType.ACCESS)


@pytest.mark.parametrize(("claim", "value"), [("iss", "evil"), ("aud", "other-api")])
def test_wrong_issuer_or_audience_rejected(claim: str, value: str) -> None:
    with pytest.raises(TokenError):
        decode_token(_sign(_claims(**{claim: value})), TokenType.ACCESS)


def test_non_uuid_subject_rejected() -> None:
    with pytest.raises(TokenError, match="subject"):
        decode_token(_sign(_claims(sub="admin")), TokenType.ACCESS)


@pytest.mark.parametrize("garbage", ["", "abc", "a.b.c", "Bearer x.y.z"])
def test_garbage_rejected(garbage: str) -> None:
    with pytest.raises(TokenError):
        decode_token(garbage, TokenType.ACCESS)

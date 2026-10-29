"""Integration tests: the auth HTTP API end to end.

Real PostgreSQL (the API connects as the restricted ``aegis_app`` role, exactly as deployed)
plus fakeredis. See tests/pg.py for how to enable these locally.
"""

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import httpx
import pyotp
import pytest
from fastapi.testclient import TestClient
from redis import Redis
from sqlalchemy import Engine, create_engine, make_url, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_migration_settings, get_settings
from app.core.redis import get_redis
from app.db.session import get_db
from app.main import create_app
from app.services import auth_service
from tests.pg import integration, migrate, require_test_db_url

pytestmark = integration

PASSWORD = "correct-horse-battery-staple"
AUTH = "/api/v1/auth"


@pytest.fixture(scope="module")
def owner_engine() -> Iterator[Engine]:
    eng = create_engine(require_test_db_url())
    migrate(eng, "downgrade")
    migrate(eng, "upgrade")
    try:
        yield eng
    finally:
        migrate(eng, "downgrade")
        eng.dispose()


@pytest.fixture(scope="module")
def app_engine(owner_engine: Engine) -> Iterator[Engine]:
    url = make_url(require_test_db_url()).set(
        username="aegis_app",
        password=get_migration_settings().app_db_password.get_secret_value(),
    )
    eng = create_engine(url)
    try:
        yield eng
    finally:
        eng.dispose()


@pytest.fixture
def api(
    owner_engine: Engine,
    app_engine: Engine,
    fake_redis: Redis,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[TestClient]:
    with owner_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))
    # Most tests make many logins; the 429 test lowers this again.
    monkeypatch.setattr(get_settings(), "rate_limit_login_requests", 1000)
    factory = sessionmaker(bind=app_engine, autoflush=False, expire_on_commit=False)

    def _db() -> Iterator[Session]:
        with factory() as session:
            yield session

    app = create_app()
    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_redis] = lambda: fake_redis
    # https so the client's cookie jar keeps Secure cookies.
    with TestClient(app, base_url="https://testserver") as client:
        yield client


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _refresh_cookie(token: str) -> dict[str, str]:
    return {"Cookie": f"aegis_refresh={token}"}


def _register(
    api: TestClient, email: str, token: str | None = None, **extra: str
) -> httpx.Response:
    body = {"email": email, "full_name": "Test User", "password": PASSWORD, **extra}
    response: httpx.Response = api.post(
        f"{AUTH}/register", json=body, headers=_bearer(token) if token else {}
    )
    return response


def _login(api: TestClient, email: str, password: str = PASSWORD) -> httpx.Response:
    response: httpx.Response = api.post(
        f"{AUTH}/login", json={"email": email, "password": password}
    )
    api.cookies.clear()  # tests pass refresh cookies explicitly
    return response


def _admin(api: TestClient) -> str:
    assert _register(api, "admin@example.com").status_code == 201
    response = _login(api, "admin@example.com")
    assert response.status_code == 200
    token: str = response.json()["access_token"]
    return token


def _user_with_login(api: TestClient, email: str = "user@example.com") -> httpx.Response:
    admin = _admin(api)
    assert _register(api, email, admin).status_code == 201
    return _login(api, email)


# --- Registration -------------------------------------------------------------------------


def test_first_user_is_bootstrapped_as_admin(api: TestClient) -> None:
    response = _register(api, "  Root@Example.COM ", role="Personnel", clearance="Top_Secret")
    assert response.status_code == 201
    body = response.json()
    assert body["role"] == "Admin"
    assert body["email"] == "root@example.com"
    assert body["clearance"] == "Top_Secret"
    assert "password_hash" not in body


def test_registration_is_admin_only_after_bootstrap(api: TestClient) -> None:
    admin = _admin(api)
    assert _register(api, "anon@example.com").status_code == 401

    created = _register(
        api, "officer@example.com", admin, role="SecurityOfficer", clearance="Secret_Level_II"
    )
    assert created.status_code == 201
    assert created.json()["role"] == "SecurityOfficer"
    assert created.json()["clearance"] == "Secret_Level_II"

    officer = _login(api, "officer@example.com").json()["access_token"]
    assert _register(api, "sneaky@example.com", officer).status_code == 403


def test_duplicate_email_is_case_insensitive(api: TestClient) -> None:
    admin = _admin(api)
    assert _register(api, "dup@example.com", admin).status_code == 201
    assert _register(api, "DUP@Example.com", admin).status_code == 409


def test_weak_password_rejected(api: TestClient) -> None:
    response = api.post(
        f"{AUTH}/register",
        json={"email": "a@example.com", "full_name": "A", "password": "short"},
    )
    assert response.status_code == 422


def test_database_rejects_mixed_case_email(owner_engine: Engine) -> None:
    with pytest.raises(IntegrityError, match="ck_users_email_lowercase"), owner_engine.begin() as c:
        c.execute(
            text(
                "INSERT INTO users (email, full_name, password_hash, role, clearance) "
                "VALUES ('Mixed@Example.com', 'M', 'h', 'Personnel', 'Reliability')"
            )
        )


# --- Login, cookies, generic errors --------------------------------------------------------


def test_login_returns_access_token_and_refresh_cookie_only(api: TestClient) -> None:
    response = _user_with_login(api)
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"access_token", "token_type", "expires_in"}
    assert body["token_type"] == "bearer"
    assert 590 <= body["expires_in"] <= 600

    cookie = response.headers["set-cookie"]
    assert cookie.startswith("aegis_refresh=")
    lowered = cookie.lower()
    assert "httponly" in lowered
    assert "samesite=strict" in lowered
    assert "path=/api/v1/auth" in lowered
    assert "secure" in lowered
    assert response.cookies["aegis_refresh"] not in response.text

    me = api.get(f"{AUTH}/me", headers=_bearer(body["access_token"]))
    assert me.status_code == 200
    assert me.json()["email"] == "user@example.com"


def test_secure_flag_is_configurable(api: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "cookie_secure", False)
    cookie = _user_with_login(api).headers["set-cookie"].lower()
    assert "secure" not in cookie
    assert "httponly" in cookie


def test_login_is_case_insensitive_on_email(api: TestClient) -> None:
    _admin(api)
    assert _login(api, "ADMIN@example.com").status_code == 200


def test_failures_are_indistinguishable(api: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    admin = _admin(api)
    _register(api, "real@example.com", admin)
    dummy_calls: list[str] = []
    real_dummy = auth_service.verify_dummy_password

    def spy(password: str) -> None:
        dummy_calls.append(password)
        real_dummy(password)

    monkeypatch.setattr(auth_service, "verify_dummy_password", spy)

    wrong_password = _login(api, "real@example.com", "not-the-password")
    unknown_user = _login(api, "ghost@example.com", "not-the-password")
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json() == unknown_user.json() == {"detail": "Invalid credentials"}
    # The unknown account still paid for one Argon2 verification.
    assert dummy_calls == ["not-the-password"]


def test_inactive_user_cannot_log_in(api: TestClient, owner_engine: Engine) -> None:
    _user_with_login(api, "gone@example.com")
    with owner_engine.begin() as conn:
        conn.execute(text("UPDATE users SET is_active = false WHERE email = 'gone@example.com'"))
    response = _login(api, "gone@example.com")
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}


# --- Lockout -------------------------------------------------------------------------------


def _lock_state(owner_engine: Engine, email: str) -> tuple[int, datetime | None]:
    with owner_engine.connect() as conn:
        row = conn.execute(
            text("SELECT failed_login_count, locked_until FROM users WHERE email = :e"),
            {"e": email},
        ).one()
    return row[0], row[1]


def test_five_failures_lock_the_account(api: TestClient, owner_engine: Engine) -> None:
    _admin(api)
    for attempt in range(1, 5):
        assert _login(api, "admin@example.com", "wrong-password").status_code == 401
        assert _lock_state(owner_engine, "admin@example.com") == (attempt, None)
    assert _login(api, "admin@example.com", "wrong-password").status_code == 401

    _, locked_until = _lock_state(owner_engine, "admin@example.com")
    assert locked_until is not None
    remaining = locked_until - datetime.now(UTC)
    assert timedelta(minutes=14) < remaining <= timedelta(minutes=15)

    # Even the correct password is refused, with the same generic error.
    locked = _login(api, "admin@example.com")
    assert locked.status_code == 401
    assert locked.json() == {"detail": "Invalid credentials"}

    with owner_engine.begin() as conn:
        conn.execute(text("UPDATE users SET locked_until = now() - interval '1 second'"))
    assert _login(api, "admin@example.com").status_code == 200
    assert _lock_state(owner_engine, "admin@example.com") == (0, None)


def test_success_resets_failure_count(api: TestClient, owner_engine: Engine) -> None:
    _admin(api)
    for _ in range(4):
        _login(api, "admin@example.com", "wrong-password")
    assert _login(api, "admin@example.com").status_code == 200
    assert _lock_state(owner_engine, "admin@example.com") == (0, None)


# --- Logout and blacklist ------------------------------------------------------------------


def test_logout_blacklists_access_and_revokes_refresh(api: TestClient) -> None:
    login = _user_with_login(api)
    access = login.json()["access_token"]
    refresh = login.cookies["aegis_refresh"]

    out = api.post(f"{AUTH}/logout", headers={**_bearer(access), **_refresh_cookie(refresh)})
    assert out.status_code == 204
    assert 'aegis_refresh=""' in out.headers["set-cookie"]

    assert api.get(f"{AUTH}/me", headers=_bearer(access)).status_code == 401
    assert api.post(f"{AUTH}/logout", headers=_bearer(access)).status_code == 401
    assert api.post(f"{AUTH}/refresh", headers=_refresh_cookie(refresh)).status_code == 401


# --- Refresh rotation ----------------------------------------------------------------------


def test_refresh_rotates_and_detects_reuse(api: TestClient) -> None:
    login = _user_with_login(api)
    first_access = login.json()["access_token"]
    first_refresh = login.cookies["aegis_refresh"]

    rotated = api.post(f"{AUTH}/refresh", headers=_refresh_cookie(first_refresh))
    assert rotated.status_code == 200
    second_refresh = rotated.cookies["aegis_refresh"]
    second_access = rotated.json()["access_token"]
    assert second_refresh != first_refresh
    assert api.get(f"{AUTH}/me", headers=_bearer(second_access)).status_code == 200

    # The old token is presented again: treated as theft.
    reused = api.post(f"{AUTH}/refresh", headers=_refresh_cookie(first_refresh))
    assert reused.status_code == 401
    assert reused.json() == {"detail": "Invalid or expired session"}
    assert 'aegis_refresh=""' in reused.headers["set-cookie"]

    # The legitimate rotated token and every access token issued so far are revoked too.
    assert api.post(f"{AUTH}/refresh", headers=_refresh_cookie(second_refresh)).status_code == 401
    for access in (first_access, second_access):
        assert api.get(f"{AUTH}/me", headers=_bearer(access)).status_code == 401


def test_refresh_requires_cookie(api: TestClient) -> None:
    assert api.post(f"{AUTH}/refresh").status_code == 401
    assert api.post(f"{AUTH}/refresh", headers=_refresh_cookie("garbage")).status_code == 401


def test_refresh_rejected_for_deactivated_user(api: TestClient, owner_engine: Engine) -> None:
    refresh = _user_with_login(api).cookies["aegis_refresh"]
    with owner_engine.begin() as conn:
        conn.execute(text("UPDATE users SET is_active = false WHERE email = 'user@example.com'"))
    assert api.post(f"{AUTH}/refresh", headers=_refresh_cookie(refresh)).status_code == 401


def test_access_token_is_not_accepted_as_refresh(api: TestClient) -> None:
    access = _user_with_login(api).json()["access_token"]
    assert api.post(f"{AUTH}/refresh", headers=_refresh_cookie(access)).status_code == 401


# --- MFA -----------------------------------------------------------------------------------


def _enroll_mfa(api: TestClient, access: str) -> pyotp.TOTP:
    setup = api.post(f"{AUTH}/mfa/setup", headers=_bearer(access))
    assert setup.status_code == 200
    body = setup.json()
    assert body["qr_code_png_base64"]
    totp = pyotp.parse_uri(body["otpauth_uri"])
    assert isinstance(totp, pyotp.TOTP)
    verify = api.post(
        f"{AUTH}/mfa/verify-setup", json={"code": totp.now()}, headers=_bearer(access)
    )
    assert verify.status_code == 200
    assert verify.json() == {"mfa_enabled": True}
    return totp


def _mfa_challenge(api: TestClient) -> str:
    response = _login(api, "user@example.com")
    assert response.status_code == 200
    body = response.json()
    assert body["mfa_required"] is True
    assert "access_token" not in body
    assert "set-cookie" not in response.headers
    token: str = body["mfa_token"]
    return token


def _code_at(totp: pyotp.TOTP, seconds: int) -> str:
    return totp.at(datetime.now(UTC) + timedelta(seconds=seconds))


def test_mfa_secret_is_stored_encrypted(api: TestClient, owner_engine: Engine) -> None:
    access = _user_with_login(api).json()["access_token"]
    totp = _enroll_mfa(api, access)
    with owner_engine.connect() as conn:
        stored = conn.execute(
            text("SELECT mfa_secret_encrypted FROM users WHERE email = 'user@example.com'")
        ).scalar_one()
    assert totp.secret not in stored


def _wrong_code(totp: pyotp.TOTP) -> str:
    """A well-formed code that is invalid in every step of the acceptance window."""
    valid = {_code_at(totp, s) for s in (-60, -30, 0, 30, 60)}
    return next(f"{n:06d}" for n in range(1_000_000) if f"{n:06d}" not in valid)


def test_verify_setup_rejects_wrong_code(api: TestClient) -> None:
    access = _user_with_login(api).json()["access_token"]
    setup = api.post(f"{AUTH}/mfa/setup", headers=_bearer(access)).json()
    totp = pyotp.parse_uri(setup["otpauth_uri"])
    assert isinstance(totp, pyotp.TOTP)
    response = api.post(
        f"{AUTH}/mfa/verify-setup", json={"code": _wrong_code(totp)}, headers=_bearer(access)
    )
    assert response.status_code == 400
    assert api.get(f"{AUTH}/me", headers=_bearer(access)).json()["mfa_enabled"] is False


def test_mfa_setup_twice_after_enable_conflicts(api: TestClient) -> None:
    access = _user_with_login(api).json()["access_token"]
    _enroll_mfa(api, access)
    assert api.post(f"{AUTH}/mfa/setup", headers=_bearer(access)).status_code == 409


def test_mfa_login_flow_and_replay_rejection(api: TestClient) -> None:
    access = _user_with_login(api).json()["access_token"]
    totp = _enroll_mfa(api, access)

    pending = _mfa_challenge(api)
    # The pending token works on no other endpoint.
    assert api.get(f"{AUTH}/me", headers=_bearer(pending)).status_code == 401
    assert api.post(f"{AUTH}/mfa/setup", headers=_bearer(pending)).status_code == 401
    assert api.post(f"{AUTH}/refresh", headers=_refresh_cookie(pending)).status_code == 401

    # The code used to confirm enrollment was consumed and cannot be replayed.
    replay = api.post(f"{AUTH}/mfa/login", json={"mfa_token": pending, "code": totp.now()})
    assert replay.status_code == 401
    assert replay.json() == {"detail": "Invalid credentials"}

    # The next time step is inside valid_window=1.
    next_code = _code_at(totp, 30)
    ok = api.post(f"{AUTH}/mfa/login", json={"mfa_token": pending, "code": next_code})
    assert ok.status_code == 200
    assert ok.cookies["aegis_refresh"]
    assert api.get(f"{AUTH}/me", headers=_bearer(ok.json()["access_token"])).status_code == 200

    # The pending token is single use, and the code cannot be replayed with a fresh one.
    again = api.post(f"{AUTH}/mfa/login", json={"mfa_token": pending, "code": _code_at(totp, -30)})
    assert again.status_code == 401
    fresh = _mfa_challenge(api)
    reused = api.post(f"{AUTH}/mfa/login", json={"mfa_token": fresh, "code": next_code})
    assert reused.status_code == 401


def test_wrong_mfa_codes_count_toward_lockout(api: TestClient, owner_engine: Engine) -> None:
    access = _user_with_login(api).json()["access_token"]
    totp = _enroll_mfa(api, access)
    wrong = _wrong_code(totp)

    pending = _mfa_challenge(api)
    for _ in range(5):
        response = api.post(f"{AUTH}/mfa/login", json={"mfa_token": pending, "code": wrong})
        assert response.status_code == 401
    _, locked_until = _lock_state(owner_engine, "user@example.com")
    assert locked_until is not None
    assert _login(api, "user@example.com").status_code == 401


def test_mfa_login_rejects_garbage_token(api: TestClient) -> None:
    response = api.post(f"{AUTH}/mfa/login", json={"mfa_token": "x.y.z", "code": "123456"})
    assert response.status_code == 401


# --- Rate limiting -------------------------------------------------------------------------


def test_login_rate_limited_per_ip_and_email(
    api: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "rate_limit_login_requests", 5)
    for _ in range(5):
        assert _login(api, "victim@example.com", "guess").status_code == 401
    blocked = _login(api, "victim@example.com", "guess")
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) >= 1
    # Same IP, other email: its own bucket.
    assert _login(api, "other@example.com", "guess").status_code == 401


def test_unused_id_in_token_is_rejected(api: TestClient) -> None:
    from app.core.security import create_refresh_token

    token = create_refresh_token(uuid.uuid4()).token
    assert api.post(f"{AUTH}/refresh", headers=_refresh_cookie(token)).status_code == 401

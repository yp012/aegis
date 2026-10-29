"""Unit tests (fakeredis + mocked DB session): get_current_user, require_roles,
require_clearance, security headers and CORS."""

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Annotated
from unittest.mock import MagicMock

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from redis import Redis
from sqlalchemy.orm import Session

from app.core.deps import require_clearance, require_roles
from app.core.redis import get_redis
from app.core.security import (
    TokenType,
    create_access_token,
    create_mfa_pending_token,
    create_refresh_token,
    decode_token,
)
from app.db.session import get_db
from app.main import create_app
from app.models.enums import Clearance, Role
from app.models.user import User
from app.services import auth_service
from tests.conftest import unreachable_redis


def _user(role: Role = Role.Personnel, clearance: Clearance = Clearance.Reliability) -> User:
    return User(
        id=uuid.uuid4(),
        email="carol@example.com",
        full_name="Carol",
        password_hash="unused",
        role=role,
        clearance=clearance,
        is_active=True,
        mfa_enabled=False,
        failed_login_count=0,
        created_at=datetime.now(UTC),
    )


class _Directory:
    """Stands in for the database: maps ids to users for ``Session.get``."""

    def __init__(self) -> None:
        self.users: dict[uuid.UUID, User] = {}
        self.session = MagicMock(spec=Session)
        self.session.get.side_effect = lambda _model, user_id: self.users.get(user_id)

    def add(self, user: User) -> str:
        self.users[user.id] = user
        return create_access_token(user).token


@pytest.fixture
def directory() -> _Directory:
    return _Directory()


@pytest.fixture
def api(fake_redis: Redis, directory: _Directory) -> Iterator[TestClient]:
    app = create_app()

    @app.get("/test/admin")
    def admin_only(user: Annotated[User, Depends(require_roles(Role.Admin))]) -> str:
        return user.email

    @app.get("/test/staff")
    def staff(
        user: Annotated[User, Depends(require_roles(Role.Admin, Role.SecurityOfficer))],
    ) -> str:
        return user.email

    @app.get("/test/top-secret")
    def top_secret(user: Annotated[User, Depends(require_clearance(Clearance.Top_Secret))]) -> str:
        return user.email

    app.dependency_overrides[get_redis] = lambda: fake_redis
    app.dependency_overrides[get_db] = lambda: directory.session
    with TestClient(app) as client:
        yield client


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_me_returns_current_user(api: TestClient, directory: _Directory) -> None:
    user = _user(clearance=Clearance.Secret_Level_II)
    response = api.get("/api/v1/auth/me", headers=_auth(directory.add(user)))
    assert response.status_code == 200
    body = response.json()
    assert body["email"] == "carol@example.com"
    assert body["clearance"] == "Secret_Level_II"
    assert "password_hash" not in body
    assert "mfa_secret_encrypted" not in body


def test_missing_token_is_401_with_challenge(api: TestClient) -> None:
    response = api.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.parametrize(
    "token_factory",
    [
        lambda uid: create_refresh_token(uid).token,
        lambda uid: create_mfa_pending_token(uid).token,
        lambda _uid: "not-a-jwt",
    ],
    ids=["refresh", "mfa_pending", "garbage"],
)
def test_non_access_tokens_rejected(
    api: TestClient, directory: _Directory, token_factory: object
) -> None:
    user = _user()
    directory.add(user)
    token = token_factory(user.id)  # type: ignore[operator]
    assert api.get("/api/v1/auth/me", headers=_auth(token)).status_code == 401


def test_blacklisted_token_rejected(
    api: TestClient, directory: _Directory, fake_redis: Redis
) -> None:
    token = directory.add(_user())
    auth_service.blacklist_access_token(fake_redis, decode_token(token, TokenType.ACCESS))
    assert api.get("/api/v1/auth/me", headers=_auth(token)).status_code == 401


def test_inactive_user_rejected(api: TestClient, directory: _Directory) -> None:
    user = _user()
    token = directory.add(user)
    user.is_active = False
    assert api.get("/api/v1/auth/me", headers=_auth(token)).status_code == 401


def test_deleted_user_rejected(api: TestClient, directory: _Directory) -> None:
    user = _user()
    token = directory.add(user)
    del directory.users[user.id]
    assert api.get("/api/v1/auth/me", headers=_auth(token)).status_code == 401


@pytest.mark.parametrize(
    ("role", "path", "expected"),
    [
        (Role.Admin, "/test/admin", 200),
        (Role.SecurityOfficer, "/test/admin", 403),
        (Role.Personnel, "/test/admin", 403),
        (Role.SecurityOfficer, "/test/staff", 200),
        (Role.Personnel, "/test/staff", 403),
    ],
)
def test_require_roles(
    api: TestClient, directory: _Directory, role: Role, path: str, expected: int
) -> None:
    response = api.get(path, headers=_auth(directory.add(_user(role=role))))
    assert response.status_code == expected


def test_role_checked_against_database_not_token(api: TestClient, directory: _Directory) -> None:
    user = _user(role=Role.Admin)
    token = directory.add(user)
    user.role = Role.Personnel  # demoted after the token was issued
    assert api.get("/test/admin", headers=_auth(token)).status_code == 403


@pytest.mark.parametrize(
    ("clearance", "expected"),
    [
        (Clearance.Reliability, 403),
        (Clearance.Secret_Level_II, 403),
        (Clearance.Top_Secret, 200),
    ],
)
def test_require_clearance(
    api: TestClient, directory: _Directory, clearance: Clearance, expected: int
) -> None:
    token = directory.add(_user(clearance=clearance))
    assert api.get("/test/top-secret", headers=_auth(token)).status_code == expected


def test_factories_reject_bad_arguments() -> None:
    with pytest.raises(ValueError, match="at least one role"):
        require_roles()
    with pytest.raises(TypeError):
        require_clearance(3)  # type: ignore[arg-type]


def test_redis_outage_fails_closed(directory: _Directory) -> None:
    app = create_app()
    down = unreachable_redis()
    app.dependency_overrides[get_redis] = lambda: down
    app.dependency_overrides[get_db] = lambda: directory.session
    with TestClient(app) as client:
        response = client.get("/api/v1/auth/me", headers=_auth(directory.add(_user())))
    assert response.status_code == 503
    assert response.json() == {"detail": "Service temporarily unavailable"}


# --- Security headers and CORS -------------------------------------------------------------


def test_security_headers_on_api_responses(client: TestClient) -> None:
    headers = client.get("/api/health").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert headers["Cache-Control"] == "no-store"
    assert headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert headers["Content-Security-Policy"].startswith("default-src 'none'")
    assert "Strict-Transport-Security" not in headers  # only in production


def test_security_headers_on_error_responses(client: TestClient) -> None:
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.headers["X-Frame-Options"] == "DENY"


def test_docs_are_not_blocked_by_api_csp(client: TestClient) -> None:
    response = client.get("/api/docs")
    assert response.status_code == 200
    assert "Content-Security-Policy" not in response.headers


def test_hsts_in_production(monkeypatch: pytest.MonkeyPatch, fake_redis: Redis) -> None:
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "environment", "production")
    app = create_app()
    app.dependency_overrides[get_redis] = lambda: fake_redis
    with TestClient(app) as client:
        response = client.get("/api/health")
        assert response.headers["Strict-Transport-Security"].startswith("max-age=")
        assert client.get("/api/docs").status_code == 404


def test_cors_allows_configured_origin(client: TestClient) -> None:
    response = client.options(
        "/api/v1/auth/login",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"},
    )
    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == "http://localhost:5173"
    assert response.headers["Access-Control-Allow-Credentials"] == "true"


def test_cors_rejects_other_origins(client: TestClient) -> None:
    response = client.options(
        "/api/v1/auth/login",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
    )
    assert response.status_code == 400
    assert "Access-Control-Allow-Origin" not in response.headers
    simple = client.get("/api/health", headers={"Origin": "https://evil.example"})
    assert "Access-Control-Allow-Origin" not in simple.headers


@pytest.mark.parametrize(
    "origins",
    ["*", "https://*.example.com", "https://a.example/path", "ftp://a.example", "a.example"],
)
def test_unsafe_cors_origins_rejected(monkeypatch: pytest.MonkeyPatch, origins: str) -> None:
    from pydantic import ValidationError

    from app.core.config import Settings

    monkeypatch.setenv("CORS_ORIGINS", origins)
    with pytest.raises(ValidationError, match="CORS origin"):
        Settings()

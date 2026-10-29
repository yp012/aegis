"""Shared pytest fixtures and test environment configuration."""

import os
from collections.abc import Iterator

import fakeredis
import pytest
from fastapi.testclient import TestClient
from redis import Redis
from redis.backoff import NoBackoff
from redis.retry import Retry

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://aegis:aegis@localhost:5432/aegis_test")
os.environ.setdefault(
    "APP_DATABASE_URL", "postgresql+psycopg://aegis_app:aegis_app@localhost:5432/aegis_test"
)
os.environ.setdefault("APP_DB_PASSWORD", "test-app-db-password-at-least-32-chars")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-key-that-is-at-least-32-chars")
os.environ.setdefault("BADGE_HMAC_SECRET", "test-badge-hmac-secret-at-least-32-chars")
# Fixed, test-only Fernet key (32 zero-bytes, base64url). Never use outside tests.
os.environ.setdefault("MFA_ENCRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")


@pytest.fixture
def fake_redis() -> Iterator[Redis]:
    """In-memory Redis with Lua support (lupa); a fresh server per test."""
    server = fakeredis.FakeServer()
    client = fakeredis.FakeRedis(server=server, decode_responses=True)
    try:
        yield client
    finally:
        client.close()


def unreachable_redis() -> Redis:
    """A client for a Redis that is down: loopback port 1 refuses at once; no retries."""
    return Redis(
        host="127.0.0.1",
        port=1,
        socket_connect_timeout=0.5,
        socket_timeout=0.5,
        retry=Retry(NoBackoff(), 0),
    )


@pytest.fixture
def client(fake_redis: Redis) -> Iterator[TestClient]:
    from app.core.redis import get_redis
    from app.main import create_app

    app = create_app()
    app.dependency_overrides[get_redis] = lambda: fake_redis
    with TestClient(app) as test_client:
        yield test_client

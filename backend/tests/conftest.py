"""Shared pytest fixtures and test environment configuration."""

import os
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://aegis:aegis@localhost:5432/aegis_test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-key-that-is-at-least-32-chars")
os.environ.setdefault("BADGE_HMAC_SECRET", "test-badge-hmac-secret-at-least-32-chars")
# Fixed, test-only Fernet key (32 zero-bytes, base64url). Never use outside tests.
os.environ.setdefault("MFA_ENCRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")


@pytest.fixture
def client() -> Iterator[TestClient]:
    from app.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client

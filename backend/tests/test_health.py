"""Smoke tests for application boot and configuration."""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings


def test_health_endpoint(client: TestClient) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_short_secret_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JWT_SECRET", "too-short")
    with pytest.raises(ValidationError):
        Settings()


def test_cors_origin_list_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CORS_ORIGINS", "https://a.example, https://b.example ,")
    assert Settings().cors_origin_list == [
        "https://a.example",
        "https://b.example",
    ]

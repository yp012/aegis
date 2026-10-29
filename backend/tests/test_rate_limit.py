"""Unit tests: sliding-window rate limiter, fail-closed behaviour, client IP resolution."""

import time
from collections.abc import Iterator

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from redis import Redis
from starlette.requests import Request

from app.core.config import Settings, get_settings
from app.core.rate_limit import RateLimiter, client_ip
from app.core.redis import get_redis
from tests.conftest import unreachable_redis


def _limiter(
    *, limit: int = 3, window: int = 60, per_email: bool = True, fail_closed: bool = True
) -> RateLimiter:
    return RateLimiter(
        "test",
        limit=lambda _: limit,
        window_seconds=lambda _: window,
        per_email=per_email,
        per_route=True,
        fail_closed=fail_closed,
    )


def _app(limiter: RateLimiter, redis: Redis) -> FastAPI:
    app = FastAPI()

    @app.post("/a", dependencies=[Depends(limiter)])
    def route_a() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/b", dependencies=[Depends(limiter)])
    def route_b() -> dict[str, bool]:
        return {"ok": True}

    app.dependency_overrides[get_redis] = lambda: redis
    return app


@pytest.fixture
def limited(fake_redis: Redis) -> Iterator[TestClient]:
    with TestClient(_app(_limiter(), fake_redis)) as client:
        yield client


def test_allows_up_to_limit_then_429_with_retry_after(limited: TestClient) -> None:
    for _ in range(3):
        assert limited.post("/a", json={"email": "a@example.com"}).status_code == 200
    blocked = limited.post("/a", json={"email": "a@example.com"})
    assert blocked.status_code == 429
    assert blocked.json() == {"detail": "Too many requests"}
    retry_after = int(blocked.headers["Retry-After"])
    assert 1 <= retry_after <= 60


def test_rejected_requests_do_not_extend_the_window(fake_redis: Redis) -> None:
    with TestClient(_app(_limiter(limit=1, window=1), fake_redis)) as client:
        assert client.post("/a").status_code == 200
        for _ in range(5):
            assert client.post("/a").status_code == 429
        time.sleep(1.1)
        assert client.post("/a").status_code == 200


def test_buckets_are_per_email(limited: TestClient) -> None:
    for _ in range(3):
        limited.post("/a", json={"email": "a@example.com"})
    assert limited.post("/a", json={"email": "a@example.com"}).status_code == 429
    assert limited.post("/a", json={"email": "b@example.com"}).status_code == 200


def test_email_is_normalised_for_bucketing(limited: TestClient) -> None:
    for email in ("A@Example.com", " a@example.com", "a@EXAMPLE.COM"):
        assert limited.post("/a", json={"email": email}).status_code == 200
    assert limited.post("/a", json={"email": "a@example.com"}).status_code == 429


def test_buckets_are_per_route(limited: TestClient) -> None:
    for _ in range(3):
        limited.post("/a", json={"email": "a@example.com"})
    assert limited.post("/a", json={"email": "a@example.com"}).status_code == 429
    assert limited.post("/b", json={"email": "a@example.com"}).status_code == 200


@pytest.mark.parametrize("body", [b"not json", b"[1, 2]", b'{"email": 5}', b""])
def test_unparseable_bodies_share_one_bucket(limited: TestClient, body: bytes) -> None:
    for _ in range(3):
        limited.post("/a", content=body)
    assert limited.post("/a", content=body).status_code == 429


def test_disabled_limiter_allows_everything(
    monkeypatch: pytest.MonkeyPatch, limited: TestClient
) -> None:
    monkeypatch.setattr(get_settings(), "rate_limit_enabled", False)
    for _ in range(10):
        assert limited.post("/a").status_code == 200


def test_auth_limiter_fails_closed_when_redis_down() -> None:
    redis = unreachable_redis()
    with TestClient(_app(_limiter(fail_closed=True), redis)) as client:
        response = client.post("/a", json={"email": "a@example.com"})
    assert response.status_code == 503
    assert response.json() == {"detail": "Service temporarily unavailable"}


def test_global_limiter_fails_open_when_redis_down() -> None:
    redis = unreachable_redis()
    with TestClient(_app(_limiter(fail_closed=False, per_email=False), redis)) as client:
        assert client.post("/a").status_code == 200


def test_global_limit_applies_to_real_app(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    monkeypatch.setattr(get_settings(), "rate_limit_default_requests", 2)
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/health").status_code == 200
    blocked = client.get("/api/health")
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers


# --- Client IP resolution ----------------------------------------------------------------------


def _request(peer: str, forwarded: str | None = None) -> Request:
    headers = [(b"x-forwarded-for", forwarded.encode())] if forwarded is not None else []
    return Request(
        {"type": "http", "method": "GET", "path": "/", "headers": headers, "client": (peer, 1)}
    )


def _settings(trusted: str) -> Settings:
    return Settings(trusted_proxies=trusted)


def test_forwarded_header_ignored_without_trusted_proxies() -> None:
    assert client_ip(_request("203.0.113.9", "198.51.100.1"), _settings("")) == "203.0.113.9"


def test_forwarded_header_ignored_from_untrusted_peer() -> None:
    request = _request("203.0.113.9", "198.51.100.1")
    assert client_ip(request, _settings("172.29.53.10")) == "203.0.113.9"


def test_forwarded_header_used_from_trusted_proxy() -> None:
    request = _request("172.29.53.10", "198.51.100.1")
    assert client_ip(request, _settings("172.29.53.10")) == "198.51.100.1"


def test_spoofed_leftmost_entries_are_ignored() -> None:
    # A client sends "X-Forwarded-For: 1.2.3.4"; a proxy appends the real address.
    request = _request("172.29.53.10", "1.2.3.4, 198.51.100.1")
    assert client_ip(request, _settings("172.29.53.0/24")) == "198.51.100.1"


def test_trusted_hops_are_skipped() -> None:
    request = _request("10.0.0.2", "198.51.100.1, 10.0.0.1")
    assert client_ip(request, _settings("10.0.0.0/8")) == "198.51.100.1"


@pytest.mark.parametrize("forwarded", ["", "not-an-ip", "10.0.0.1"])
def test_falls_back_to_peer_without_usable_header(forwarded: str) -> None:
    request = _request("10.0.0.2", forwarded)
    assert client_ip(request, _settings("10.0.0.0/8")) == "10.0.0.2"


def test_invalid_trusted_proxies_rejected() -> None:
    with pytest.raises(ValueError, match="TRUSTED_PROXIES"):
        Settings(trusted_proxies="nginx")

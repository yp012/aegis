"""Redis-backed request rate limiting.

A sliding-window log: each allowed request is a member of a sorted set scored by its
timestamp. The Lua script trims entries older than the window, counts what is left, and
records the new request only if it is under the limit, all in one atomic step, so concurrent
requests across API replicas cannot overshoot. Time comes from Redis (``TIME``), not from
each API process, so replicas with skewed clocks agree on the window.

Auth limiters fail closed (503) when Redis is unavailable, because an attacker who can knock
Redis over must not gain unlimited password guesses. The global limiter fails open so an
outage does not take down unrelated read endpoints.
"""

import ipaddress
import json
import logging
import math
import secrets
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from redis import Redis
from redis.exceptions import RedisError

from app.core.config import Settings, get_settings
from app.core.redis import get_redis, key

logger = logging.getLogger(__name__)

SLIDING_WINDOW_LUA = """
local now_parts = redis.call('TIME')
local now = tonumber(now_parts[1]) * 1000 + math.floor(tonumber(now_parts[2]) / 1000)
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
local count = redis.call('ZCARD', KEYS[1])
if count < limit then
    redis.call('ZADD', KEYS[1], now, now .. '-' .. ARGV[3])
    redis.call('PEXPIRE', KEYS[1], window)
    return {1, 0}
end
local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
local retry = window
if oldest[2] then
    retry = tonumber(oldest[2]) + window - now
end
return {0, retry}
"""


def client_ip(request: Request, settings: Settings | None = None) -> str:
    """Return the real client IP.

    ``X-Forwarded-For`` is honoured only when the TCP peer is a configured trusted proxy
    (the nginx edge). The header is then read right to left, skipping trusted hops, so
    addresses a client prepends itself are never used.
    """
    settings = settings or get_settings()
    peer = request.client.host if request.client else ""
    networks = settings.trusted_proxy_networks
    if not networks or not _in_networks(peer, networks):
        return peer or "unknown"
    forwarded = request.headers.get("x-forwarded-for", "")
    for hop in reversed([part.strip() for part in forwarded.split(",") if part.strip()]):
        if not _is_ip(hop):
            break
        if not _in_networks(hop, networks):
            return hop
    return peer


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _in_networks(value: str, networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(addr in net for net in networks)


async def _email_from_body(request: Request) -> str:
    """Best-effort, normalised ``email`` from a JSON body; FastAPI has already buffered it."""
    try:
        payload = json.loads(await request.body() or b"{}")
    except (ValueError, UnicodeDecodeError):
        return "-"
    email = payload.get("email") if isinstance(payload, dict) else None
    return email.strip().lower()[:320] if isinstance(email, str) and email.strip() else "-"


class RateLimiter:
    """FastAPI dependency enforcing ``limit`` requests per ``window`` for one scope.

    With ``per_route`` each endpoint gets its own bucket, so e.g. refreshing a session does
    not consume the login allowance.
    """

    def __init__(
        self,
        scope: str,
        *,
        limit: Callable[[Settings], int],
        window_seconds: Callable[[Settings], int],
        per_email: bool,
        per_route: bool,
        fail_closed: bool,
    ) -> None:
        self.scope = scope
        self._limit = limit
        self._window_seconds = window_seconds
        self.per_email = per_email
        self.per_route = per_route
        self.fail_closed = fail_closed

    async def __call__(self, request: Request, redis: Annotated[Redis, Depends(get_redis)]) -> None:
        settings = get_settings()
        if not settings.rate_limit_enabled:
            return
        identity = client_ip(request, settings)
        if self.per_email:
            identity = f"{identity}|{await _email_from_body(request)}"
        bucket = (
            key("ratelimit", self.scope, request.url.path, identity)
            if self.per_route
            else key("ratelimit", self.scope, identity)
        )
        limit = self._limit(settings)
        window_ms = self._window_seconds(settings) * 1000
        try:
            allowed, retry_ms = await run_in_threadpool(
                redis.eval,
                SLIDING_WINDOW_LUA,
                1,
                bucket,
                window_ms,
                limit,
                secrets.token_hex(8),
            )
        except RedisError:
            if self.fail_closed:
                logger.error("rate limiter unavailable; failing closed for scope %s", self.scope)
                raise HTTPException(
                    status.HTTP_503_SERVICE_UNAVAILABLE, "Service temporarily unavailable"
                ) from None
            logger.warning("rate limiter unavailable; failing open for scope %s", self.scope)
            return
        if not int(allowed):
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "Too many requests",
                headers={"Retry-After": str(max(1, math.ceil(int(retry_ms) / 1000)))},
            )


global_rate_limit = RateLimiter(
    "global",
    limit=lambda s: s.rate_limit_default_requests,
    window_seconds=lambda s: s.rate_limit_default_window_seconds,
    per_email=False,
    per_route=False,
    fail_closed=False,
)

auth_rate_limit = RateLimiter(
    "auth",
    limit=lambda s: s.rate_limit_login_requests,
    window_seconds=lambda s: s.rate_limit_login_window_seconds,
    per_email=True,
    per_route=True,
    fail_closed=True,
)

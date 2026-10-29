"""Redis client lifecycle.

One process-wide connection pool, created lazily from ``REDIS_URL``. Routes and dependencies
receive the client through ``Depends(get_redis)`` so tests can substitute fakeredis.
Short socket timeouts make an unreachable Redis fail fast instead of hanging requests.
"""

from functools import lru_cache

from redis import Redis

KEY_PREFIX = "aegis"


@lru_cache
def _client() -> Redis:
    from app.core.config import get_settings

    return Redis.from_url(
        get_settings().redis_url,
        decode_responses=True,
        socket_timeout=2,
        socket_connect_timeout=2,
        health_check_interval=30,
    )


def get_redis() -> Redis:
    return _client()


def close_redis() -> None:
    if _client.cache_info().currsize:
        _client().close()
        _client.cache_clear()


def key(*parts: str) -> str:
    """Namespaced Redis key, e.g. ``key("blacklist", jti)`` -> ``aegis:blacklist:<jti>``."""
    return ":".join((KEY_PREFIX, *parts))

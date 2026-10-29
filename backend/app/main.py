"""FastAPI application entrypoint."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from redis.exceptions import RedisError
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.rate_limit import global_rate_limit
from app.core.redis import close_redis

logger = logging.getLogger(__name__)

# Swagger UI loads its assets from a CDN, so it cannot run under the API's deny-all CSP.
# These paths only exist outside production.
_DOCS_PATHS = frozenset({"/api/docs", "/api/docs/oauth2-redirect", "/api/openapi.json"})

_API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"


class SecurityHeadersMiddleware:
    """Adds defensive headers to every HTTP response (pure ASGI, so it also covers errors
    raised by routes and dependencies). Headers a route set explicitly are left alone."""

    def __init__(self, app: ASGIApp, *, hsts: bool) -> None:
        self.app = app
        self.headers: dict[str, str] = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            # Responses carry tokens and personal data; never let a cache keep them.
            "Cache-Control": "no-store",
        }
        if hsts:
            self.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        is_docs = scope["path"] in _DOCS_PATHS

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in self.headers.items():
                    headers.setdefault(name, value)
                if not is_docs:
                    headers.setdefault("Content-Security-Policy", _API_CSP)
            await send(message)

        await self.app(scope, receive, send_with_headers)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    yield
    close_redis()


async def _redis_unavailable(_: Request, exc: Exception) -> JSONResponse:
    # Revocation lists, refresh tokens and TOTP replay state live in Redis; without it the
    # API cannot make a safe auth decision, so it refuses rather than guessing.
    logger.error("redis unavailable: %s", type(exc).__name__)
    return JSONResponse(
        {"detail": "Service temporarily unavailable"},
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
    )


def create_app() -> FastAPI:
    settings = get_settings()
    is_prod = settings.environment == "production"

    app = FastAPI(
        title=settings.app_name,
        debug=settings.debug,
        docs_url=None if is_prod else "/api/docs",
        redoc_url=None,
        openapi_url=None if is_prod else "/api/openapi.json",
        lifespan=lifespan,
        dependencies=[Depends(global_rate_limit)],
    )

    app.add_exception_handler(RedisError, _redis_unavailable)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
        max_age=600,
    )
    # Added last so it is the outermost layer and also decorates CORS preflight responses.
    app.add_middleware(SecurityHeadersMiddleware, hsts=is_prod)

    @app.get("/api/health", tags=["health"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(api_router, prefix=settings.api_v1_prefix)
    return app


app = create_app()

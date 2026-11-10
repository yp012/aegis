"""Aggregates all v1 API routers."""

from fastapi import APIRouter

from app.api.v1 import audit, auth, users, zones

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(zones.router)
api_router.include_router(audit.router)

"""Shared helpers for the PostgreSQL integration tests.

Opt-in locally: set AEGIS_TEST_DATABASE_URL to a *disposable* PostgreSQL database (as the
schema owner). Integration modules downgrade it to base before and after running. In CI
(CI=true) they are never skipped, so a missing database fails the build.
"""

import os
from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy import Engine
from sqlalchemy.exc import DBAPIError

from alembic import command

TEST_DB_URL = os.environ.get("AEGIS_TEST_DATABASE_URL")
IN_CI = os.environ.get("CI", "").lower() == "true"

integration = [
    pytest.mark.integration,
    pytest.mark.skipif(not TEST_DB_URL and not IN_CI, reason="AEGIS_TEST_DATABASE_URL not set"),
]

ALEMBIC_INI = Path(__file__).resolve().parents[1] / "alembic.ini"


def require_test_db_url() -> str:
    if TEST_DB_URL is None:
        pytest.fail("AEGIS_TEST_DATABASE_URL must be set in CI; integration tests may not skip")
    return TEST_DB_URL


def migrate(engine: Engine, action: str) -> None:
    cfg = Config(str(ALEMBIC_INI))
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        if action == "upgrade":
            command.upgrade(cfg, "head")
        else:
            command.downgrade(cfg, "base")


def sqlstate(exc: DBAPIError) -> str | None:
    return getattr(exc.orig, "sqlstate", None)

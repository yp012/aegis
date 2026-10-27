"""Integration tests: Alembic round-trip and DB-level audit log immutability.

Opt-in locally: set AEGIS_TEST_DATABASE_URL to a *disposable* PostgreSQL database. The
tests downgrade it to base (dropping every table) before and after running. In CI (CI=true)
they are never skipped, so a missing database fails the build instead of passing silently.
"""

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from alembic import command

TEST_DB_URL = os.environ.get("AEGIS_TEST_DATABASE_URL")
IN_CI = os.environ.get("CI", "").lower() == "true"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not TEST_DB_URL and not IN_CI, reason="AEGIS_TEST_DATABASE_URL not set"),
]

ALEMBIC_INI = Path(__file__).resolve().parents[1] / "alembic.ini"
RESTRICT_VIOLATION = "23001"


def _migrate(engine: Engine, action: str) -> None:
    cfg = Config(str(ALEMBIC_INI))
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        if action == "upgrade":
            command.upgrade(cfg, "head")
        else:
            command.downgrade(cfg, "base")


@pytest.fixture(scope="module")
def engine() -> Iterator[Engine]:
    if TEST_DB_URL is None:
        pytest.fail("AEGIS_TEST_DATABASE_URL must be set in CI; integration tests may not skip")
    eng = create_engine(TEST_DB_URL)
    _migrate(eng, "downgrade")
    _migrate(eng, "upgrade")
    try:
        yield eng
    finally:
        _migrate(eng, "downgrade")
        eng.dispose()


@pytest.fixture(scope="module")
def seeded(engine: Engine) -> Engine:
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_logs (prev_hash, entry_hash, action, resource) "
                "VALUES (repeat('0', 64), repeat('a', 64), 'system.init', 'audit_logs')"
            )
        )
    return engine


def _sqlstate(exc: DBAPIError) -> str | None:
    return getattr(exc.orig, "sqlstate", None)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_logs SET action = 'tampered'",
        "DELETE FROM audit_logs",
        "DELETE FROM audit_logs WHERE false",
        "TRUNCATE audit_logs",
    ],
)
def test_audit_log_rejects_mutation(seeded: Engine, statement: str) -> None:
    with pytest.raises(DBAPIError) as excinfo, seeded.begin() as conn:
        conn.execute(text(statement))
    assert _sqlstate(excinfo.value) == RESTRICT_VIOLATION
    assert "append-only" in str(excinfo.value)

    with seeded.connect() as conn:
        assert conn.execute(text("SELECT action FROM audit_logs")).scalars().all() == [
            "system.init"
        ]


def test_audit_log_allows_insert(seeded: Engine) -> None:
    with seeded.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_logs (prev_hash, entry_hash, action, resource) "
                "VALUES (repeat('a', 64), repeat('b', 64), 'user.login', 'users')"
            )
        )
    with seeded.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM audit_logs")).scalar_one() == 2


def test_grant_requires_exactly_one_subject(engine: Engine) -> None:
    with engine.begin() as conn:
        user_id = conn.execute(
            text(
                "INSERT INTO users (email, full_name, password_hash, role, clearance) "
                "VALUES ('grant@test.io', 'G', 'h', 'Admin', 'Top_Secret') RETURNING id"
            )
        ).scalar_one()
        zone_id = conn.execute(
            text(
                "INSERT INTO zones (name, min_clearance, capacity) "
                "VALUES ('Grant Test Zone', 'Reliability', 1) RETURNING id"
            )
        ).scalar_one()

    insert = text(
        "INSERT INTO zone_access_grants (user_id, visitor_id, zone_id, granted_by, expires_at) "
        "VALUES (:u, NULL, :z, :g, now() + interval '1 hour')"
    )
    with pytest.raises(IntegrityError, match="exactly_one_subject"), engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO zone_access_grants (zone_id, granted_by, expires_at) "
                "VALUES (:z, :g, now() + interval '1 hour')"
            ),
            {"z": zone_id, "g": user_id},
        )
    with engine.begin() as conn:
        conn.execute(insert, {"u": user_id, "z": zone_id, "g": user_id})


def test_pg_clearance_ordering(engine: Engine) -> None:
    with engine.connect() as conn:
        labels = conn.execute(text("SELECT unnest(enum_range(NULL::clearance))::text")).scalars()
        assert list(labels) == ["Reliability", "Secret_Level_II", "Top_Secret"]


def test_downgrade_then_upgrade_round_trips(engine: Engine) -> None:
    _migrate(engine, "downgrade")
    with engine.connect() as conn:
        leftovers = conn.execute(
            text(
                "SELECT (SELECT count(*) FROM pg_tables WHERE schemaname = 'public' "
                "        AND tablename <> 'alembic_version')"
                " + (SELECT count(*) FROM pg_type t JOIN pg_namespace n "
                "    ON n.oid = t.typnamespace WHERE n.nspname = 'public' AND t.typtype = 'e')"
                " + (SELECT count(*) FROM pg_proc WHERE proname = 'audit_logs_reject_mutation')"
            )
        ).scalar_one()
    assert leftovers == 0

    _migrate(engine, "upgrade")
    with engine.connect() as conn:
        trigger = conn.execute(
            text(
                "SELECT count(*) FROM pg_trigger "
                "WHERE tgname = 'audit_log_immutable' AND tgrelid = 'audit_logs'::regclass"
            )
        ).scalar_one()
    assert trigger == 1

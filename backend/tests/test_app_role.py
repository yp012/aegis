"""Integration tests: the restricted `aegis_app` role cannot bypass audit immutability.

The API connects as `aegis_app` (APP_DATABASE_URL). These tests log in as that role with
APP_DB_PASSWORD against the database at AEGIS_TEST_DATABASE_URL (see tests/pg.py) and prove
it can append to and read the audit trail, but cannot mutate it or switch the trigger off.
"""

from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, create_engine, make_url, text
from sqlalchemy.exc import DBAPIError

from app.core.config import get_migration_settings
from tests.pg import integration, migrate, require_test_db_url, sqlstate

pytestmark = integration

APP_ROLE = "aegis_app"
INSUFFICIENT_PRIVILEGE = "42501"


@pytest.fixture(scope="module")
def owner_engine() -> Iterator[Engine]:
    eng = create_engine(require_test_db_url())
    migrate(eng, "downgrade")
    migrate(eng, "upgrade")
    with eng.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_logs (prev_hash, entry_hash, action, resource) "
                "VALUES (repeat('0', 64), repeat('c', 64), 'system.init', 'audit_logs')"
            )
        )
    try:
        yield eng
    finally:
        migrate(eng, "downgrade")
        eng.dispose()


@pytest.fixture(scope="module")
def app_engine(owner_engine: Engine) -> Iterator[Engine]:
    url = make_url(require_test_db_url()).set(
        username=APP_ROLE,
        password=get_migration_settings().app_db_password.get_secret_value(),
    )
    eng = create_engine(url)
    try:
        yield eng
    finally:
        eng.dispose()


def _audit_actions(owner_engine: Engine) -> list[str]:
    with owner_engine.connect() as conn:
        return list(conn.execute(text("SELECT action FROM audit_logs ORDER BY id")).scalars())


def test_app_logs_in_as_restricted_role(app_engine: Engine) -> None:
    with app_engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT current_user, r.rolsuper, r.rolcreatedb, r.rolcreaterole, "
                "r.rolreplication, r.rolbypassrls "
                "FROM pg_roles r WHERE r.rolname = current_user"
            )
        ).one()
    assert row == (APP_ROLE, False, False, False, False, False)


def test_app_role_owns_nothing_and_inherits_nothing(owner_engine: Engine) -> None:
    with owner_engine.connect() as conn:
        owned = conn.execute(
            text(
                "SELECT (SELECT count(*) FROM pg_class WHERE relowner = CAST(:r AS regrole))"
                " + (SELECT count(*) FROM pg_namespace WHERE nspowner = CAST(:r AS regrole))"
                " + (SELECT count(*) FROM pg_proc WHERE proowner = CAST(:r AS regrole))"
                " + (SELECT count(*) FROM pg_type WHERE typowner = CAST(:r AS regrole))"
            ),
            {"r": APP_ROLE},
        ).scalar_one()
        memberships = conn.execute(
            text("SELECT count(*) FROM pg_auth_members WHERE member = CAST(:r AS regrole)"),
            {"r": APP_ROLE},
        ).scalar_one()
    assert owned == 0
    assert memberships == 0


@pytest.mark.parametrize(
    ("privilege", "expected"),
    [
        ("SELECT", True),
        ("INSERT", True),
        ("UPDATE", False),
        ("DELETE", False),
        ("TRUNCATE", False),
        ("REFERENCES", False),
        ("TRIGGER", False),
    ],
)
def test_audit_logs_privileges(owner_engine: Engine, privilege: str, expected: bool) -> None:
    with owner_engine.connect() as conn:
        held = conn.execute(
            text("SELECT has_table_privilege(:r, 'audit_logs', :p)"),
            {"r": APP_ROLE, "p": privilege},
        ).scalar_one()
    assert held is expected


def test_app_can_insert_and_select_audit_logs(app_engine: Engine) -> None:
    with app_engine.begin() as conn:
        new_id = conn.execute(
            text(
                "INSERT INTO audit_logs (prev_hash, entry_hash, action, resource) "
                "VALUES (repeat('c', 64), repeat('d', 64), 'user.login', 'users') RETURNING id"
            )
        ).scalar_one()
    with app_engine.connect() as conn:
        action = conn.execute(
            text("SELECT action FROM audit_logs WHERE id = :id"), {"id": new_id}
        ).scalar_one()
    assert action == "user.login"


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_logs SET action = 'tampered'",
        "DELETE FROM audit_logs",
        "DELETE FROM audit_logs WHERE false",
        "TRUNCATE audit_logs",
        "DROP TABLE audit_logs",
        "DROP TABLE zones",
        "ALTER TABLE audit_logs DISABLE TRIGGER audit_log_immutable",
        "ALTER TABLE audit_logs DISABLE TRIGGER ALL",
        "DROP TRIGGER audit_log_immutable ON audit_logs",
        "SET session_replication_role = replica",
        "CREATE TABLE public.shadow_audit (id int)",
        "SELECT version_num FROM alembic_version",
    ],
)
def test_app_cannot_tamper(owner_engine: Engine, app_engine: Engine, statement: str) -> None:
    before = _audit_actions(owner_engine)
    with pytest.raises(DBAPIError) as excinfo, app_engine.begin() as conn:
        conn.execute(text(statement))
    assert sqlstate(excinfo.value) == INSUFFICIENT_PRIVILEGE
    assert _audit_actions(owner_engine) == before
    assert "system.init" in before


def test_app_cannot_assume_owner_role(app_engine: Engine) -> None:
    owner = make_url(require_test_db_url()).username
    with pytest.raises(DBAPIError) as excinfo, app_engine.begin() as conn:
        conn.execute(text(f'SET ROLE "{owner}"'))
    assert sqlstate(excinfo.value) == INSUFFICIENT_PRIVILEGE


def test_app_has_full_dml_on_regular_tables(app_engine: Engine) -> None:
    with app_engine.begin() as conn:
        zone_id = conn.execute(
            text(
                "INSERT INTO zones (name, min_clearance, capacity) "
                "VALUES ('Role Test Zone', 'Reliability', 2) RETURNING id"
            )
        ).scalar_one()
        conn.execute(text("UPDATE zones SET capacity = 3 WHERE id = :id"), {"id": zone_id})
        deleted = conn.execute(text("DELETE FROM zones WHERE id = :id"), {"id": zone_id})
    assert deleted.rowcount == 1

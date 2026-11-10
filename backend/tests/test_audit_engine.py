"""Integration tests: the tamper-evident audit engine against real PostgreSQL.

Appends run as the restricted ``aegis_app`` role, exactly as deployed. Tampering is done
through the schema owner with the immutability trigger switched off for one transaction,
which is what an attacker holding owner or superuser credentials could do; the tests then
check that ``verify_chain`` pinpoints it. Also covered: concurrent writers, the trigger and
role guarantees on real entries, and the ``/audit`` endpoints. See tests/pg.py.
"""

import random
import threading
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from redis import Redis
from sqlalchemy import Engine, create_engine, make_url, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_migration_settings, get_settings
from app.core.redis import get_redis
from app.db.session import get_db
from app.main import create_app
from app.models.audit import GENESIS_HASH, AuditLog
from app.models.enums import Clearance
from app.services import audit_chain
from app.services.audit_chain import VerificationReport
from tests.pg import integration, migrate, require_test_db_url, reset_data, sqlstate

pytestmark = integration

PASSWORD = "correct-horse-battery-staple"
V1 = "/api/v1"
INSUFFICIENT_PRIVILEGE = "42501"
RESTRICT_VIOLATION = "23001"
THREADS = 50
APPENDS_PER_THREAD = 4


@pytest.fixture(scope="module")
def owner_engine() -> Iterator[Engine]:
    eng = create_engine(require_test_db_url())
    migrate(eng, "downgrade")
    migrate(eng, "upgrade")
    try:
        yield eng
    finally:
        migrate(eng, "downgrade")
        eng.dispose()


@pytest.fixture(scope="module")
def app_engine(owner_engine: Engine) -> Iterator[Engine]:
    url = make_url(require_test_db_url()).set(
        username="aegis_app",
        password=get_migration_settings().app_db_password.get_secret_value(),
    )
    # One connection per concurrent writer in the concurrency test.
    eng = create_engine(url, pool_size=THREADS, max_overflow=0)
    try:
        yield eng
    finally:
        eng.dispose()


@pytest.fixture
def sessions(owner_engine: Engine, app_engine: Engine) -> sessionmaker[Session]:
    reset_data(owner_engine)
    return sessionmaker(bind=app_engine, autoflush=False, expire_on_commit=False)


def _append(
    factory: sessionmaker[Session],
    count: int,
    *,
    per_commit: int = 1,
    actor_id: uuid.UUID | None = None,
) -> None:
    with factory() as db:
        for i in range(count):
            audit_chain.append(
                db,
                actor_id,
                "test.event",
                f"things/{i}",
                {
                    "n": i,
                    "label": f"entrée #{i} ✓",  # non-ASCII survives JSONB and ensure_ascii
                    "ref": uuid.UUID(int=i),
                    "clearance": Clearance.Secret_Level_II,
                    "nested": {"b": [i, None, True], "a": {"z": "", "y": -i}},
                },
            )
            if (i + 1) % per_commit == 0:
                db.commit()
        db.commit()


def _verify(factory: sessionmaker[Session], **kwargs: Any) -> VerificationReport:
    with factory() as db:
        return audit_chain.verify_chain(db, **kwargs)


def _tamper(owner_engine: Engine, *statements: tuple[str, dict[str, Any]]) -> None:
    """Run ``statements`` as the owner with the immutability trigger off (test-only)."""
    with owner_engine.begin() as conn:
        conn.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER audit_log_immutable"))
        for sql, params in statements:
            conn.execute(text(sql), params)
        conn.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER audit_log_immutable"))


def _kinds(report: VerificationReport) -> set[tuple[int | None, str]]:
    return {(issue.id, issue.kind) for issue in report.issues}


# --- Healthy chain --------------------------------------------------------------------------


def test_thousand_entries_verify(sessions: sessionmaker[Session]) -> None:
    _append(sessions, 1000, per_commit=7)  # several entries per transaction too
    report = _verify(sessions)
    assert report.ok, report.issues
    assert (report.total, report.verified, report.broken_ids) == (1000, 1000, [])
    assert report.first_broken_id is None
    assert report.checkpoint == "ok"
    assert report.duration_ms > 0
    assert report.logs_per_second > 0

    # Small batches exercise the keyset streaming; ranges link to the entry before them.
    assert _verify(sessions, batch_size=64).verified == 1000
    ranged = _verify(sessions, start_id=400, end_id=650, batch_size=100)
    assert (ranged.ok, ranged.total, ranged.checkpoint) == (True, 251, "not_checked")
    assert _verify(sessions, start_id=990).total == 11


def test_ids_are_gapless_and_linked(sessions: sessionmaker[Session], owner_engine: Engine) -> None:
    _append(sessions, 10)
    with owner_engine.connect() as conn:
        rows = conn.execute(text("SELECT id, prev_hash, entry_hash FROM audit_logs ORDER BY id"))
        chain = rows.all()
        checkpoint = conn.execute(text("SELECT head_id, head_hash FROM audit_checkpoint")).one()
    assert [r[0] for r in chain] == list(range(1, 11))
    assert chain[0][1] == GENESIS_HASH
    assert all(chain[i][1] == chain[i - 1][2] for i in range(1, 10))
    assert tuple(checkpoint) == (10, chain[-1][2])


def test_rolled_back_append_leaves_no_gap(sessions: sessionmaker[Session]) -> None:
    _append(sessions, 3)
    with sessions() as db:
        audit_chain.append(db, None, "test.rolled_back", "things/x", {})
        db.rollback()
    _append(sessions, 2)
    report = _verify(sessions)
    assert report.ok
    assert report.total == 5


def test_stored_timestamp_is_exactly_the_hashed_one(
    sessions: sessionmaker[Session], owner_engine: Engine
) -> None:
    with sessions() as db:
        entry = audit_chain.append(db, None, "test.event", "things/1", {})
        db.commit()
    # A different session time zone must not change what verification reads back.
    with owner_engine.connect() as conn:
        conn.execute(text("SET TIME ZONE 'Asia/Kathmandu'"))
        stored = conn.execute(
            text("SELECT created_at FROM audit_logs WHERE id = :id"), {"id": entry.id}
        ).scalar_one()
    assert stored == entry.created_at
    assert audit_chain.format_timestamp(stored) == audit_chain.format_timestamp(entry.created_at)
    with Session(owner_engine) as db:
        db.execute(text("SET TIME ZONE 'America/St_Johns'"))
        assert audit_chain.verify_chain(db).ok


# --- Tampering ------------------------------------------------------------------------------


def test_modified_payload_reports_exactly_that_id(
    sessions: sessionmaker[Session], owner_engine: Engine
) -> None:
    _append(sessions, 200)
    victim = random.Random(20261109).randint(1, 200)  # noqa: S311 (not crypto)
    _tamper(
        owner_engine,
        (
            "UPDATE audit_logs SET payload = jsonb_set(payload, '{n}', '123456') WHERE id = :id",
            {"id": victim},
        ),
    )
    report = _verify(sessions)
    assert not report.ok
    assert report.broken_ids == [victim]
    assert report.first_broken_id == victim
    assert _kinds(report) == {(victim, "hash_mismatch")}
    assert report.verified == 199
    assert report.checkpoint == "ok"


@pytest.mark.parametrize(
    "assignment",
    [
        "action = 'zone.delete'",
        "resource = 'zones/elsewhere'",
        "actor_id = NULL",
        "created_at = created_at + interval '1 microsecond'",
        "entry_hash = repeat('e', 64)",
    ],
)
def test_every_modified_column_is_detected(
    sessions: sessionmaker[Session], owner_engine: Engine, assignment: str
) -> None:
    with owner_engine.begin() as conn:
        actor = conn.execute(
            text(
                "INSERT INTO users (email, full_name, password_hash, role, clearance) "
                "VALUES ('actor@test.io', 'A', 'h', 'Admin', 'Top_Secret') RETURNING id"
            )
        ).scalar_one()
    _append(sessions, 20, actor_id=actor)
    _tamper(owner_engine, (f"UPDATE audit_logs SET {assignment} WHERE id = 12", {}))  # noqa: S608
    report = _verify(sessions)
    assert report.first_broken_id == 12
    assert not report.ok


def test_modified_prev_hash_linkage_is_detected(
    sessions: sessionmaker[Session], owner_engine: Engine
) -> None:
    _append(sessions, 30)
    _tamper(owner_engine, ("UPDATE audit_logs SET prev_hash = repeat('b', 64) WHERE id = 9", {}))
    report = _verify(sessions)
    assert report.broken_ids == [9]
    assert _kinds(report) == {(9, "broken_link"), (9, "hash_mismatch")}


def test_deleted_middle_row_is_detected(
    sessions: sessionmaker[Session], owner_engine: Engine
) -> None:
    _append(sessions, 30)
    _tamper(owner_engine, ("DELETE FROM audit_logs WHERE id = 15", {}))
    report = _verify(sessions)
    assert not report.ok
    assert report.broken_ids == [16]
    assert _kinds(report) == {(16, "gap"), (16, "broken_link")}
    assert report.checkpoint == "ok"


def test_reordered_rows_are_detected(sessions: sessionmaker[Session], owner_engine: Engine) -> None:
    _append(sessions, 30)
    _tamper(
        owner_engine,
        ("UPDATE audit_logs SET id = 1000000 WHERE id = 10", {}),
        ("UPDATE audit_logs SET id = 10 WHERE id = 11", {}),
        ("UPDATE audit_logs SET id = 11 WHERE id = 1000000", {}),
    )
    report = _verify(sessions)
    assert not report.ok
    assert report.first_broken_id == 10
    assert {10, 11} <= set(report.broken_ids)


def test_tail_truncation_is_detected_and_survives_later_appends(
    sessions: sessionmaker[Session], owner_engine: Engine
) -> None:
    _append(sessions, 25)
    _tamper(owner_engine, ("DELETE FROM audit_logs WHERE id > 22", {}))

    report = _verify(sessions)
    assert not report.ok
    assert report.checkpoint == "truncated"
    assert report.first_broken_id == 23
    assert _kinds(report) == {(23, "truncated")}
    # The surviving 22 entries are internally consistent; only the checkpoint shows the loss.
    assert report.verified == 22

    # The next append records the divergence inside the chain instead of overwriting the
    # evidence with a fresh checkpoint.
    _append(sessions, 1)
    after = _verify(sessions)
    assert not after.ok
    assert after.checkpoint == "ok"
    assert _kinds(after) == {(23, "divergence_recorded")}
    with sessions() as db:
        record = db.get(AuditLog, 23)
        assert record is not None
        assert record.action == audit_chain.DIVERGENCE_ACTION
        assert record.payload["reason"] == "chain_truncated"
        assert (record.payload["checkpoint_head_id"], record.payload["found_head_id"]) == (25, 22)


def test_rewritten_tail_with_forged_checkpoint_is_detected(
    sessions: sessionmaker[Session], owner_engine: Engine
) -> None:
    _append(sessions, 10)
    # Without the HMAC key the attacker can only write a checkpoint that does not verify.
    _tamper(
        owner_engine,
        ("DELETE FROM audit_logs WHERE id > 8", {}),
        (
            "UPDATE audit_checkpoint SET head_id = 8, "
            "head_hash = (SELECT entry_hash FROM audit_logs WHERE id = 8)",
            {},
        ),
    )
    report = _verify(sessions)
    assert report.checkpoint == "invalid_signature"
    assert not report.ok


def test_replaced_head_entry_is_detected(
    sessions: sessionmaker[Session], owner_engine: Engine
) -> None:
    _append(sessions, 10)
    # Delete the head and re-insert a self-consistent forgery in its place.
    with sessions() as db:
        prev_hash = db.get(AuditLog, 9).entry_hash  # type: ignore[union-attr]
    moment = datetime.now(UTC)
    forged = audit_chain.compute_entry_hash(
        prev_hash, 10, None, "test.forged", "things/x", {}, audit_chain.format_timestamp(moment)
    )
    _tamper(
        owner_engine,
        ("DELETE FROM audit_logs WHERE id = 10", {}),
        (
            "INSERT INTO audit_logs (id, prev_hash, entry_hash, action, resource, created_at) "
            "VALUES (10, :p, :h, 'test.forged', 'things/x', :t)",
            {"p": prev_hash, "h": forged, "t": moment},
        ),
    )
    report = _verify(sessions)
    assert report.checkpoint == "mismatch"
    assert report.broken_ids == [10]
    assert _kinds(report) == {(10, "checkpoint_mismatch")}


def test_deleted_checkpoint_is_detected(
    sessions: sessionmaker[Session], owner_engine: Engine
) -> None:
    _append(sessions, 5)
    _tamper(owner_engine, ("DELETE FROM audit_checkpoint", {}))
    report = _verify(sessions)
    assert report.checkpoint == "missing"
    assert not report.ok


def test_empty_chain_is_healthy(sessions: sessionmaker[Session]) -> None:
    report = _verify(sessions)
    assert (report.ok, report.total, report.checkpoint) == (True, 0, "empty")


# --- Concurrency ----------------------------------------------------------------------------


def test_concurrent_appends_never_fork(
    sessions: sessionmaker[Session], owner_engine: Engine
) -> None:
    barrier = threading.Barrier(THREADS)
    errors: list[BaseException] = []

    def writer(worker: int) -> None:
        try:
            barrier.wait(timeout=30)
            for step in range(APPENDS_PER_THREAD):
                with sessions() as db:
                    audit_chain.append(
                        db, None, "test.concurrent", f"workers/{worker}", {"step": step}
                    )
                    db.commit()
        except BaseException as exc:  # surfaced below; a thread cannot fail the test itself
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)
    assert not errors, errors

    expected = THREADS * APPENDS_PER_THREAD
    report = _verify(sessions)
    assert report.ok, report.issues
    assert report.total == expected
    with owner_engine.connect() as conn:
        forks = conn.execute(
            text("SELECT prev_hash FROM audit_logs GROUP BY prev_hash HAVING count(*) > 1")
        ).all()
        ids = conn.execute(text("SELECT id FROM audit_logs ORDER BY id")).scalars().all()
        head = conn.execute(text("SELECT head_id FROM audit_checkpoint")).scalar_one()
    assert forks == []
    assert ids == list(range(1, expected + 1))
    assert head == expected


# --- Database guarantees on real entries ----------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_logs SET payload = '{}'::jsonb WHERE id = 2",
        "DELETE FROM audit_logs WHERE id = 3",
        "DELETE FROM audit_logs",
        "TRUNCATE audit_logs",
    ],
)
def test_trigger_and_app_role_block_mutation(
    sessions: sessionmaker[Session], owner_engine: Engine, app_engine: Engine, statement: str
) -> None:
    _append(sessions, 3)
    # The API's role lacks the privilege outright.
    with pytest.raises(DBAPIError) as as_app, app_engine.begin() as conn:
        conn.execute(text(statement))
    assert sqlstate(as_app.value) == INSUFFICIENT_PRIVILEGE
    # Even the owner is stopped by the trigger while it is enabled.
    with pytest.raises(DBAPIError) as as_owner, owner_engine.begin() as conn:
        conn.execute(text(statement))
    assert sqlstate(as_owner.value) == RESTRICT_VIOLATION
    report = _verify(sessions)
    assert (report.ok, report.total) == (True, 3)


def test_app_role_cannot_remove_the_checkpoint(
    sessions: sessionmaker[Session], app_engine: Engine
) -> None:
    _append(sessions, 1)
    with pytest.raises(DBAPIError) as excinfo, app_engine.begin() as conn:
        conn.execute(text("DELETE FROM audit_checkpoint"))
    assert sqlstate(excinfo.value) == INSUFFICIENT_PRIVILEGE


# --- HTTP API -------------------------------------------------------------------------------


@pytest.fixture
def api(
    sessions: sessionmaker[Session], fake_redis: Redis, monkeypatch: pytest.MonkeyPatch
) -> Iterator[TestClient]:
    monkeypatch.setattr(get_settings(), "rate_limit_login_requests", 1000)
    monkeypatch.setattr(get_settings(), "rate_limit_default_requests", 10_000)

    def _db() -> Iterator[Session]:
        with sessions() as session:
            yield session

    app = create_app()
    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_redis] = lambda: fake_redis
    with TestClient(app, base_url="https://testserver") as client:
        yield client


def _token(api: TestClient, email: str) -> dict[str, str]:
    response = api.post(f"{V1}/auth/login", json={"email": email, "password": PASSWORD})
    api.cookies.clear()
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture
def staff(api: TestClient) -> dict[str, dict[str, str]]:
    def register(email: str, headers: dict[str, str] | None, **extra: str) -> None:
        body = {"email": email, "full_name": "Staff", "password": PASSWORD, **extra}
        response = api.post(f"{V1}/auth/register", json=body, headers=headers or {})
        assert response.status_code == 201, response.text

    register("admin@example.com", None, clearance="Top_Secret")
    admin = _token(api, "admin@example.com")
    register("officer@example.com", admin, role="SecurityOfficer")
    register("worker@example.com", admin)
    return {
        "admin": admin,
        "officer": _token(api, "officer@example.com"),
        "worker": _token(api, "worker@example.com"),
    }


def test_audit_endpoints_require_officer_or_admin(
    api: TestClient, staff: dict[str, dict[str, str]]
) -> None:
    for path in ("/audit/logs", "/audit/verify"):
        assert api.get(f"{V1}{path}").status_code == 401
        assert api.get(f"{V1}{path}", headers=staff["worker"]).status_code == 403
        assert api.get(f"{V1}{path}", headers=staff["officer"]).status_code == 200
        assert api.get(f"{V1}{path}", headers=staff["admin"]).status_code == 200


def test_logs_are_paginated_newest_first(
    api: TestClient, staff: dict[str, dict[str, str]], sessions: sessionmaker[Session]
) -> None:
    _append(sessions, 12)
    first = api.get(f"{V1}/audit/logs?page=1&page_size=5", headers=staff["officer"]).json()
    total = first["total"]
    assert total >= 12
    assert (first["page"], first["page_size"]) == (1, 5)
    assert [item["id"] for item in first["items"]] == list(range(total, total - 5, -1))
    second = api.get(f"{V1}/audit/logs?page=2&page_size=5", headers=staff["officer"]).json()
    assert [item["id"] for item in second["items"]] == list(range(total - 5, total - 10, -1))
    item = first["items"][0]
    assert set(item) == {
        "id", "prev_hash", "entry_hash", "actor_id", "action", "resource", "payload",
        "created_at",
    }  # fmt: skip
    beyond = api.get(f"{V1}/audit/logs?page=999", headers=staff["officer"]).json()
    assert beyond["items"] == []
    for bad in ("page=0", "page_size=0", "page_size=201"):
        assert api.get(f"{V1}/audit/logs?{bad}", headers=staff["officer"]).status_code == 422


def test_verify_returns_report_and_is_itself_audited(
    api: TestClient, staff: dict[str, dict[str, str]], sessions: sessionmaker[Session]
) -> None:
    response = api.get(f"{V1}/audit/verify", headers=staff["officer"])
    assert response.status_code == 200
    report = response.json()
    assert report["ok"] is True
    assert report["checkpoint"] == "ok"
    assert report["total"] == report["verified"] > 0
    assert report["broken_ids"] == []
    assert {"duration_ms", "logs_per_second", "first_broken_id", "issues"} <= set(report)

    with sessions() as db:
        entry = db.get(AuditLog, report["audit_entry_id"])
        assert entry is not None
        assert entry.action == "audit.verify"
        assert entry.payload["ok"] is True
        assert entry.payload["total"] == report["total"]
        assert entry.id == report["total"] + 1  # recorded right after what it checked

    # The next verification covers the previous one's audit entry too.
    again = api.get(f"{V1}/audit/verify", headers=staff["admin"]).json()
    assert again["ok"] is True
    assert again["total"] == report["total"] + 1


def test_verify_reports_tampering_over_http(
    api: TestClient,
    staff: dict[str, dict[str, str]],
    sessions: sessionmaker[Session],
    owner_engine: Engine,
) -> None:
    _append(sessions, 5)
    _tamper(owner_engine, ("UPDATE audit_logs SET action = 'rewritten' WHERE id = 2", {}))
    report = api.get(f"{V1}/audit/verify", headers=staff["officer"]).json()
    assert report["ok"] is False
    assert report["broken_ids"] == [2]
    assert [(i["id"], i["kind"]) for i in report["issues"]] == [(2, "hash_mismatch")]
    with sessions() as db:
        entry = db.get(AuditLog, report["audit_entry_id"])
        assert entry is not None
        assert (entry.payload["ok"], entry.payload["first_broken_id"]) == (False, 2)


def test_verify_validates_ranges(api: TestClient, staff: dict[str, dict[str, str]]) -> None:
    headers = staff["officer"]
    assert api.get(f"{V1}/audit/verify?start_id=0", headers=headers).status_code == 422
    assert api.get(f"{V1}/audit/verify?start_id=5&end_id=2", headers=headers).status_code == 422
    ranged = api.get(f"{V1}/audit/verify?start_id=1&end_id=2", headers=headers).json()
    assert (ranged["total"], ranged["checkpoint"], ranged["ok"]) == (2, "not_checked", True)

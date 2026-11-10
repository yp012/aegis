"""Unit tests (no database): the audit engine's canonical encoding, hashing, checkpoint
signing, append staging (mocked session) and the streaming chain verifier; plus pure
request-level guards (``assert_may_assign``, ``GrantCreate``) that do not need PostgreSQL.

The same scenarios against real PostgreSQL live in tests/test_audit_engine.py.
"""

import dataclasses
import enum
import hashlib
import uuid
from datetime import UTC, datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session

from app.api.v1.users import assert_may_assign
from app.core.config import get_settings
from app.models.audit import GENESIS_HASH, AuditLog
from app.models.enums import Clearance, Role, SubjectType
from app.models.user import User
from app.schemas.zone import GrantCreate
from app.services import audit_chain
from app.services.audit_chain import ChainRow, ChainVerifier, VerificationReport

ACTOR = uuid.UUID("00000000-0000-4000-8000-000000000001")
MOMENT = datetime(2026, 11, 9, 12, 0, 0, 123456, tzinfo=UTC)
ISO = "2026-11-09T12:00:00.123456Z"


# --- Canonical encoding and hashing ---------------------------------------------------------


def test_entry_hash_matches_the_documented_formula() -> None:
    payload = {"name": "Lobby", "capacity": 3}
    expected_body = (
        '{"action":"zone.create","actor_id":"00000000-0000-4000-8000-000000000001",'
        '"created_at_iso":"2026-11-09T12:00:00.123456Z","id_seq":7,'
        '"payload":{"capacity":3,"name":"Lobby"},"resource":"zones/1"}'
    )
    expected = hashlib.sha256((GENESIS_HASH + expected_body).encode()).hexdigest()
    assert (
        audit_chain.compute_entry_hash(
            GENESIS_HASH, 7, ACTOR, "zone.create", "zones/1", payload, ISO
        )
        == expected
    )


def _hash(**overrides: Any) -> str:
    fields: dict[str, Any] = {
        "prev_hash": GENESIS_HASH,
        "id_seq": 1,
        "actor_id": ACTOR,
        "action": "a",
        "resource": "r",
        "payload": {"k": 1},
        "created_at_iso": ISO,
    }
    fields.update(overrides)
    return audit_chain.compute_entry_hash(**fields)


def test_hash_changes_with_every_field() -> None:
    variants = [
        _hash(prev_hash="1" * 64),
        _hash(id_seq=2),
        _hash(actor_id=None),
        _hash(action="b"),
        _hash(resource="s"),
        _hash(payload={"k": 2}),
        _hash(payload={"k": "1"}),
        _hash(created_at_iso="2026-11-09T12:00:00.123457Z"),
    ]
    assert _hash() not in variants
    assert len(set(variants)) == len(variants)


def test_hash_ignores_payload_key_order() -> None:
    assert _hash(payload={"x": 1, "y": {"b": 2, "a": 3}}) == _hash(
        payload={"y": {"a": 3, "b": 2}, "x": 1}
    )


def test_canonical_json_is_ascii_sorted_and_compact() -> None:
    assert audit_chain.canonical_json({"b": "é", "a": [1, None, True]}) == (
        '{"a":[1,null,true],"b":"\\u00e9"}'
    )
    with pytest.raises(ValueError):
        audit_chain.canonical_json({"x": float("nan")})


def test_timestamp_is_utc_microseconds_with_z() -> None:
    assert audit_chain.format_timestamp(MOMENT) == ISO
    assert audit_chain.format_timestamp(MOMENT.replace(microsecond=0)).endswith(".000000Z")
    plus_five = MOMENT.astimezone(timezone(timedelta(hours=5)))
    assert audit_chain.format_timestamp(plus_five) == ISO
    with pytest.raises(ValueError, match="timezone-aware"):
        audit_chain.format_timestamp(datetime(2026, 11, 9, 12, 0))


def test_payload_is_normalised_to_json_types() -> None:
    body = audit_chain.canonical_payload(
        {"id": ACTOR, "at": MOMENT, "clearance": Clearance.Top_Secret, "role": Role.Admin}
    )
    assert body == {
        "id": str(ACTOR),
        "at": "2026-11-09T12:00:00.123456+00:00",
        "clearance": "Top_Secret",  # by name, never the bare int 3
        "role": "Admin",
    }


@pytest.mark.parametrize("value", [object(), 1.5, b"bytes", {1, 2}])
def test_unserialisable_payload_is_rejected(value: object) -> None:
    with pytest.raises(TypeError, match="not serialisable"):
        audit_chain.canonical_payload({"x": value})


def test_enum_by_name() -> None:
    class Colour(enum.Enum):
        RED = 1

    assert audit_chain.canonical_payload({"c": Colour.RED}) == {"c": "RED"}


# --- Checkpoint signature -------------------------------------------------------------------


def test_checkpoint_signature_round_trip() -> None:
    signature = audit_chain.sign_checkpoint(5, "a" * 64)
    assert len(signature) == 64
    assert audit_chain.checkpoint_signature_valid(5, "a" * 64, signature)
    assert not audit_chain.checkpoint_signature_valid(4, "a" * 64, signature)
    assert not audit_chain.checkpoint_signature_valid(5, "b" * 64, signature)
    assert not audit_chain.checkpoint_signature_valid(5, "a" * 64, "0" * 64)


def test_checkpoint_signature_depends_on_the_key(monkeypatch: pytest.MonkeyPatch) -> None:
    signature = audit_chain.sign_checkpoint(5, "a" * 64)
    settings = get_settings()
    monkeypatch.setattr(settings, "audit_hmac_secret", type(settings.audit_hmac_secret)("k" * 40))
    assert not audit_chain.checkpoint_signature_valid(5, "a" * 64, signature)


# --- Append (mocked session) ----------------------------------------------------------------


def _result(value: object) -> MagicMock:
    result = MagicMock()
    result.one_or_none.return_value = value
    return result


def _session(head: tuple[int, str] | None, checkpoint: tuple[int, str, str] | None) -> MagicMock:
    db = MagicMock(spec=Session)
    # lock, head, checkpoint, then (one or more) inserts are flushed and the checkpoint upserted.
    db.execute.side_effect = [_result(None), _result(head), _result(checkpoint)] + [
        _result(None)
    ] * 3
    return db


def _checkpoint_for(head_id: int, head_hash: str) -> tuple[int, str, str]:
    return (head_id, head_hash, audit_chain.sign_checkpoint(head_id, head_hash))


def _upserted(db: MagicMock) -> dict[str, Any]:
    stmt = db.execute.call_args_list[-1].args[0]
    params: dict[str, Any] = stmt.compile(dialect=postgresql.dialect()).params
    return params


def _added(db: MagicMock) -> list[AuditLog]:
    return [c.args[0] for c in db.add.call_args_list]


def test_first_entry_is_id_one_linked_to_genesis() -> None:
    db = _session(None, None)
    entry = audit_chain.append(db, ACTOR, "zone.create", "zones/1", {"name": "Lobby"})
    assert isinstance(entry, AuditLog)
    assert (entry.id, entry.prev_hash) == (1, GENESIS_HASH)
    assert (entry.actor_id, entry.action, entry.resource, entry.payload) == (
        ACTOR,
        "zone.create",
        "zones/1",
        {"name": "Lobby"},
    )
    assert entry.created_at.tzinfo is not None
    assert entry.entry_hash == audit_chain.compute_entry_hash(
        GENESIS_HASH,
        1,
        ACTOR,
        "zone.create",
        "zones/1",
        {"name": "Lobby"},
        audit_chain.format_timestamp(entry.created_at),
    )
    assert _added(db) == [entry]
    db.flush.assert_called_once_with()
    # The caller owns the transaction: append never commits.
    db.commit.assert_not_called()

    params = _upserted(db)
    assert (params["head_id"], params["head_hash"]) == (1, entry.entry_hash)
    assert audit_chain.checkpoint_signature_valid(1, entry.entry_hash, params["signature"])


def test_entry_follows_the_checkpointed_head() -> None:
    previous = "a" * 64
    db = _session((41, previous), _checkpoint_for(41, previous))
    entry = audit_chain.append(db, None, "user.bootstrap", "users/x", None)
    assert (entry.id, entry.prev_hash, entry.payload) == (42, previous, {})
    assert _added(db) == [entry]
    assert _upserted(db)["head_id"] == 42


@pytest.mark.parametrize(
    ("head", "checkpoint", "reason"),
    [
        ((3, "c" * 64), None, "checkpoint_missing"),
        ((3, "c" * 64), (3, "c" * 64, "0" * 64), "checkpoint_invalid"),
        ((3, "c" * 64), _checkpoint_for(5, "e" * 64), "chain_truncated"),
        (None, _checkpoint_for(5, "e" * 64), "chain_truncated"),
        ((6, "f" * 64), _checkpoint_for(5, "e" * 64), "unanchored_entries"),
        ((5, "f" * 64), _checkpoint_for(5, "e" * 64), "head_mismatch"),
    ],
)
def test_divergent_head_is_recorded_before_the_entry(
    head: tuple[int, str] | None, checkpoint: tuple[int, str, str] | None, reason: str
) -> None:
    db = _session(head, checkpoint)
    entry = audit_chain.append(db, ACTOR, "zone.create", "zones/1", {})
    divergence, added = _added(db)
    assert added is entry
    assert divergence.action == audit_chain.DIVERGENCE_ACTION
    assert divergence.actor_id is None
    assert divergence.payload["reason"] == reason
    assert divergence.payload["found_head_id"] == (head[0] if head else None)
    assert divergence.payload["checkpoint_head_id"] == (checkpoint[0] if checkpoint else None)
    # The divergence record is chained in and the requested entry follows it.
    assert divergence.id == (head[0] if head else 0) + 1
    assert (entry.id, entry.prev_hash) == (divergence.id + 1, divergence.entry_hash)
    assert _upserted(db)["head_id"] == entry.id


def test_unserialisable_payload_fails_before_touching_the_db() -> None:
    db = _session(None, None)
    with pytest.raises(TypeError):
        audit_chain.append(db, ACTOR, "a", "r", {"x": 0.5})
    db.execute.assert_not_called()


# --- Streaming verifier ---------------------------------------------------------------------


def _chain(length: int) -> list[ChainRow]:
    rows: list[ChainRow] = []
    prev = GENESIS_HASH
    for i in range(1, length + 1):
        created = MOMENT + timedelta(microseconds=i * 7)
        payload: dict[str, Any] = {"n": i, "nested": {"z": [1, "two"], "a": None}}
        entry_hash = audit_chain.compute_entry_hash(
            prev,
            i,
            ACTOR,
            "test.event",
            f"things/{i}",
            payload,
            audit_chain.format_timestamp(created),
        )
        rows.append(
            ChainRow(i, prev, entry_hash, ACTOR, "test.event", f"things/{i}", payload, created)
        )
        prev = entry_hash
    return rows


def _verify(rows: list[ChainRow]) -> VerificationReport:
    verifier = ChainVerifier()
    for row in rows:
        verifier.feed(row)
    return verifier.finish(
        checkpoint="not_checked", start_id=None, end_id=None, elapsed_seconds=0.5
    )


def _kinds(report: VerificationReport) -> set[tuple[int | None, str]]:
    return {(issue.id, issue.kind) for issue in report.issues}


def test_intact_chain_verifies() -> None:
    report = _verify(_chain(50))
    assert report.ok
    assert (report.total, report.verified, report.broken_ids) == (50, 50, [])
    assert report.first_broken_id is None
    assert report.logs_per_second == 100.0


def _reversed_keys(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _reversed_keys(value[k]) for k in reversed(list(value))}
    return value


def test_db_round_trip_shapes_still_verify() -> None:
    # What PostgreSQL hands back: JSONB keys in another order, timestamps in the session zone.
    rows = [
        row._replace(
            payload=_reversed_keys(row.payload),
            created_at=row.created_at.astimezone(timezone(timedelta(hours=-7))),
        )
        for row in _chain(5)
    ]
    assert list(rows[0].payload) == ["nested", "n"]
    assert _verify(rows).ok


def test_modified_payload_flags_exactly_that_row() -> None:
    rows = _chain(20)
    rows[9] = rows[9]._replace(payload={**rows[9].payload, "n": 999})
    report = _verify(rows)
    assert not report.ok
    assert report.broken_ids == [10]
    assert _kinds(report) == {(10, "hash_mismatch")}
    assert report.verified == 19


@pytest.mark.parametrize(
    "change",
    [
        {"actor_id": None},
        {"action": "other"},
        {"resource": "elsewhere"},
        {"created_at": MOMENT + timedelta(days=1)},
        {"entry_hash": "f" * 64},
    ],
)
def test_any_modified_column_is_detected(change: dict[str, Any]) -> None:
    rows = _chain(5)
    rows[2] = rows[2]._replace(**change)
    report = _verify(rows)
    assert 3 in report.broken_ids
    assert report.first_broken_id == 3


def test_modified_prev_hash_breaks_link_and_hash() -> None:
    rows = _chain(10)
    rows[4] = rows[4]._replace(prev_hash="b" * 64)
    report = _verify(rows)
    assert report.broken_ids == [5]
    assert _kinds(report) == {(5, "broken_link"), (5, "hash_mismatch")}


def test_deleted_middle_row_is_a_gap_and_broken_link() -> None:
    rows = _chain(10)
    del rows[4]  # id 5
    report = _verify(rows)
    assert report.broken_ids == [6]
    assert _kinds(report) == {(6, "gap"), (6, "broken_link")}
    assert report.total == 9


def test_deleted_first_row_is_detected() -> None:
    report = _verify(_chain(3)[1:])
    assert report.first_broken_id == 2
    assert (2, "gap") in _kinds(report)


def test_reordered_rows_are_detected() -> None:
    rows = _chain(10)
    # Swap the positions (ids) of entries 5 and 6, as an UPDATE of the ids would.
    five, six = rows[4], rows[5]
    rows[4] = six._replace(id=5)
    rows[5] = five._replace(id=6)
    report = _verify(rows)
    assert report.first_broken_id == 5
    assert {5, 6} <= set(report.broken_ids)


def test_recorded_divergence_keeps_the_chain_unhealthy() -> None:
    rows = _chain(3)
    created = MOMENT + timedelta(seconds=1)
    payload = {"reason": "chain_truncated"}
    entry_hash = audit_chain.compute_entry_hash(
        rows[-1].entry_hash,
        4,
        None,
        audit_chain.DIVERGENCE_ACTION,
        "audit_logs",
        payload,
        audit_chain.format_timestamp(created),
    )
    rows.append(
        ChainRow(
            4,
            rows[-1].entry_hash,
            entry_hash,
            None,
            audit_chain.DIVERGENCE_ACTION,
            "audit_logs",
            payload,
            created,
        )
    )
    report = _verify(rows)
    assert not report.ok
    assert _kinds(report) == {(4, "divergence_recorded")}


def test_unhealthy_checkpoint_fails_the_report() -> None:
    verifier = ChainVerifier()
    for row in _chain(3):
        verifier.feed(row)
    report = verifier.finish(checkpoint="missing", start_id=None, end_id=None, elapsed_seconds=0)
    assert not report.ok
    assert report.broken_ids == []
    assert report.logs_per_second == 0.0


def test_report_lists_are_bounded() -> None:
    verifier = ChainVerifier()
    for row in _chain(audit_chain.MAX_REPORTED + 5):
        verifier.feed(row._replace(entry_hash="0" * 64))
    report = verifier.finish(checkpoint="ok", start_id=None, end_id=None, elapsed_seconds=1)
    assert report.broken_count == audit_chain.MAX_REPORTED + 5
    assert len(report.broken_ids) == len(report.issues) == audit_chain.MAX_REPORTED
    assert dataclasses.asdict(report)["broken_count"] == report.broken_count


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"start_id": 0}, "start_id"),
        ({"start_id": 5, "end_id": 4}, "end_id"),
        ({"batch_size": 0}, "batch_size"),
    ],
)
def test_verify_chain_rejects_bad_ranges(kwargs: dict[str, int], message: str) -> None:
    db = MagicMock(spec=Session)
    with pytest.raises(audit_chain.AuditChainError, match=message):
        audit_chain.verify_chain(db, **kwargs)
    db.execute.assert_not_called()


# --- Role / clearance assignment guard ----------------------------------------------------


def _actor(role: Role) -> User:
    return User(id=uuid.uuid4(), role=role, clearance=Clearance.Top_Secret, is_active=True)


@pytest.mark.parametrize("role", [Role.SecurityOfficer, Role.Personnel])
@pytest.mark.parametrize(
    ("new_role", "new_clearance"),
    [(Role.Admin, None), (None, Clearance.Top_Secret), (Role.Admin, Clearance.Top_Secret)],
)
def test_only_admin_may_assign_admin_or_top_secret(
    role: Role, new_role: Role | None, new_clearance: Clearance | None
) -> None:
    with pytest.raises(HTTPException) as exc:
        assert_may_assign(_actor(role), new_role, new_clearance)
    assert exc.value.status_code == 403
    assert_may_assign(_actor(Role.Admin), new_role, new_clearance)


def test_non_admin_may_assign_lesser_values() -> None:
    assert_may_assign(_actor(Role.SecurityOfficer), Role.Personnel, Clearance.Secret_Level_II)


# --- GrantCreate --------------------------------------------------------------------------


def test_grant_create_requires_exactly_one_subject() -> None:
    expires = datetime.now(UTC) + timedelta(days=1)
    user_id, visitor_id = uuid.uuid4(), uuid.uuid4()
    assert GrantCreate(user_id=user_id, expires_at=expires).subject() == (SubjectType.User, user_id)
    assert GrantCreate(visitor_id=visitor_id, expires_at=expires).subject() == (
        SubjectType.Visitor,
        visitor_id,
    )
    with pytest.raises(ValidationError, match="exactly one"):
        GrantCreate(user_id=user_id, visitor_id=visitor_id, expires_at=expires)
    with pytest.raises(ValidationError, match="exactly one"):
        GrantCreate(expires_at=expires)


def test_grant_create_requires_aware_expiry() -> None:
    with pytest.raises(ValidationError):
        GrantCreate(user_id=uuid.uuid4(), expires_at=datetime(2030, 1, 1))

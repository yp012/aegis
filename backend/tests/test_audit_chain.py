"""Unit tests (mocked DB session): the audit append hook, plus pure request-level guards
(``assert_may_assign``, ``GrantCreate``) that do not need PostgreSQL."""

import enum
import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.api.v1.users import assert_may_assign
from app.models.audit import GENESIS_HASH, AuditLog
from app.models.enums import Clearance, Role, SubjectType
from app.models.user import User
from app.schemas.zone import GrantCreate
from app.services import audit_chain

ACTOR = uuid.UUID("00000000-0000-4000-8000-000000000001")


def _session(previous_hash: str | None) -> MagicMock:
    db = MagicMock(spec=Session)
    db.scalar.return_value = previous_hash
    return db


def test_first_entry_links_to_genesis() -> None:
    db = _session(None)
    entry = audit_chain.append(db, ACTOR, "zone.create", "zones/1", {"name": "Lobby"})
    assert isinstance(entry, AuditLog)
    assert entry.prev_hash == GENESIS_HASH
    assert entry.actor_id == ACTOR
    assert (entry.action, entry.resource, entry.payload) == (
        "zone.create",
        "zones/1",
        {"name": "Lobby"},
    )
    db.add.assert_called_once_with(entry)
    db.flush.assert_called_once_with()
    # The caller owns the transaction: append never commits.
    db.commit.assert_not_called()


def test_entry_links_to_previous_hash_and_hash_is_reproducible() -> None:
    previous = "a" * 64
    entry = audit_chain.append(_session(previous), None, "user.bootstrap", "users/x", None)
    assert entry.prev_hash == previous
    assert entry.payload == {}
    expected_body = json.dumps(
        {
            "action": "user.bootstrap",
            "actor_id": None,
            "payload": {},
            "prev_hash": previous,
            "resource": "users/x",
        },
        separators=(",", ":"),
    )
    assert entry.entry_hash == hashlib.sha256(expected_body.encode()).hexdigest()


def test_hash_changes_with_any_field() -> None:
    base = audit_chain.compute_entry_hash(GENESIS_HASH, ACTOR, "a", "r", {"k": 1})
    variants = [
        audit_chain.compute_entry_hash("1" * 64, ACTOR, "a", "r", {"k": 1}),
        audit_chain.compute_entry_hash(GENESIS_HASH, None, "a", "r", {"k": 1}),
        audit_chain.compute_entry_hash(GENESIS_HASH, ACTOR, "b", "r", {"k": 1}),
        audit_chain.compute_entry_hash(GENESIS_HASH, ACTOR, "a", "s", {"k": 1}),
        audit_chain.compute_entry_hash(GENESIS_HASH, ACTOR, "a", "r", {"k": 2}),
    ]
    assert base not in variants
    assert len(set(variants)) == len(variants)


def test_hash_ignores_payload_key_order() -> None:
    a = audit_chain.compute_entry_hash(GENESIS_HASH, ACTOR, "a", "r", {"x": 1, "y": 2})
    b = audit_chain.compute_entry_hash(GENESIS_HASH, ACTOR, "a", "r", {"y": 2, "x": 1})
    assert a == b


def test_payload_is_normalised_to_json_types() -> None:
    moment = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)
    body = audit_chain.canonical_payload(
        {"id": ACTOR, "at": moment, "clearance": Clearance.Top_Secret, "role": Role.Admin}
    )
    assert body == {
        "id": str(ACTOR),
        "at": "2026-11-09T12:00:00+00:00",
        "clearance": "Top_Secret",  # by name, never the bare int 3
        "role": "Admin",
    }


def test_unserialisable_payload_is_rejected() -> None:
    class Opaque:
        pass

    with pytest.raises(TypeError, match="Opaque"):
        audit_chain.canonical_payload({"x": Opaque()})


def test_enum_by_name() -> None:
    class Colour(enum.Enum):
        RED = 1

    assert audit_chain.canonical_payload({"c": Colour.RED}) == {"c": "RED"}


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

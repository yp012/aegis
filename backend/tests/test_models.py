"""Metadata-level tests for ORM models (no database required)."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import CheckConstraint, DateTime, Enum, Uuid
from sqlalchemy.dialects.postgresql import JSONB

import app.models  # noqa: F401  (registers all tables)
from app.db.base import Base
from app.models import AuditCheckpoint, AuditLog, ZoneAccessGrant

EXPECTED_TABLES = {
    "users",
    "zones",
    "zone_access_grants",
    "visitors",
    "badges",
    "access_events",
    "audit_logs",
    "audit_checkpoint",
}


def _check_names(table_name: str) -> set[str]:
    table = Base.metadata.tables[table_name]
    return {str(c.name) for c in table.constraints if isinstance(c, CheckConstraint)}


def test_all_tables_registered() -> None:
    assert set(Base.metadata.tables) == EXPECTED_TABLES


@pytest.mark.parametrize("table_name", sorted(EXPECTED_TABLES - {"audit_logs", "audit_checkpoint"}))
def test_uuid_primary_keys(table_name: str) -> None:
    (pk,) = Base.metadata.tables[table_name].primary_key.columns
    assert isinstance(pk.type, Uuid)
    assert pk.server_default is not None


def test_audit_log_uses_app_assigned_bigint_ids_and_jsonb() -> None:
    table = AuditLog.__table__
    assert table.c.id.type.__visit_name__ == "big_integer"
    # Gapless ids come from audit_chain.append, never from a sequence.
    assert table.c.id.autoincrement is False
    assert table.c.id.server_default is None
    assert "ck_audit_logs_id_positive" in _check_names("audit_logs")
    assert isinstance(table.c.payload.type, JSONB)
    assert table.c.entry_hash.unique is True


def test_audit_checkpoint_is_a_constrained_singleton() -> None:
    assert AuditCheckpoint.__table__.c.id.autoincrement is False
    assert {
        "ck_audit_checkpoint_singleton",
        "ck_audit_checkpoint_head_id_positive",
        "ck_audit_checkpoint_head_hash_is_sha256_hex",
        "ck_audit_checkpoint_signature_is_hmac_sha256_hex",
    } <= _check_names("audit_checkpoint")


def test_every_datetime_is_timezone_aware() -> None:
    datetime_types = {
        str(col): col.type
        for table in Base.metadata.tables.values()
        for col in table.columns
        if isinstance(col.type, DateTime)
    }
    assert datetime_types
    naive = [name for name, typ in datetime_types.items() if not typ.timezone]
    assert naive == []


def test_enums_are_native_pg_types() -> None:
    names = {
        col.type.name
        for table in Base.metadata.tables.values()
        for col in table.columns
        if isinstance(col.type, Enum)
    }
    assert names == {
        "role",
        "clearance",
        "visitor_type",
        "visitor_status",
        "subject_type",
        "access_result",
    }
    for table in Base.metadata.tables.values():
        for col in table.columns:
            if isinstance(col.type, Enum):
                assert col.type.native_enum is True


def test_grant_exactly_one_subject_constraint_present() -> None:
    assert "ck_zone_access_grants_exactly_one_subject" in _check_names("zone_access_grants")


def test_zone_occupancy_constraints_present() -> None:
    assert {
        "ck_zones_capacity_positive",
        "ck_zones_occupancy_within_capacity",
    } <= _check_names("zones")


def _grant(expires_in: timedelta, revoked_ago: timedelta | None = None) -> ZoneAccessGrant:
    now = datetime.now(UTC)
    return ZoneAccessGrant(
        expires_at=now + expires_in,
        revoked_at=None if revoked_ago is None else now - revoked_ago,
    )


def test_grant_validity_window() -> None:
    now = datetime.now(UTC)
    assert _grant(timedelta(hours=1)).is_valid_at(now) is True
    assert _grant(timedelta(seconds=-1)).is_valid_at(now) is False
    assert _grant(timedelta(hours=1), revoked_ago=timedelta(minutes=1)).is_valid_at(now) is False


def test_grant_validity_rejects_naive_datetime() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        _grant(timedelta(hours=1)).is_valid_at(datetime.now())

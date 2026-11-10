"""Append-only SHA-256 hash-chained audit log.

``append`` is the single entry point every mutation and access decision goes through. It adds
the entry to the caller's session without committing, so the audit row and the change it
describes land in the same transaction: either both are recorded or neither is.

Each entry's hash covers the previous entry's hash plus its own canonical content. Appends are
serialised with a transaction-scoped advisory lock so two concurrent writers cannot both link
to the same predecessor and fork the chain.
"""

import enum
import hashlib
import json
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.audit import GENESIS_HASH, AuditLog

# Arbitrary constant key for pg_advisory_xact_lock; released when the transaction ends.
_APPEND_LOCK_ID = 0xA0D17


def _normalise(value: Any) -> Any:
    # Enums are checked first: IntEnum/StrEnum members are also int/str, and json.dumps would
    # otherwise write Clearance.Top_Secret as a bare 3 without consulting any default hook.
    if isinstance(value, enum.Enum):
        return value.name
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _normalise(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_normalise(v) for v in value]
    if value is None or isinstance(value, bool | int | float | str):
        return value
    raise TypeError(f"audit payload value of type {type(value).__name__} is not serialisable")


def canonical_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalise ``payload`` to plain JSON types (UUIDs, datetimes and enums become strings)."""
    normalised: dict[str, Any] = _normalise(payload)
    return normalised


def compute_entry_hash(
    prev_hash: str,
    actor_id: uuid.UUID | None,
    action: str,
    resource: str,
    payload: dict[str, Any],
) -> str:
    body = json.dumps(
        {
            "prev_hash": prev_hash,
            "actor_id": str(actor_id) if actor_id is not None else None,
            "action": action,
            "resource": resource,
            "payload": payload,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def append(
    db: Session,
    actor_id: uuid.UUID | None,
    action: str,
    resource: str,
    payload: dict[str, Any] | None = None,
) -> AuditLog:
    """Stage one audit entry in ``db``'s current transaction (the caller commits)."""
    db.execute(select(func.pg_advisory_xact_lock(_APPEND_LOCK_ID)))
    prev_hash = (
        db.scalar(select(AuditLog.entry_hash).order_by(AuditLog.id.desc()).limit(1)) or GENESIS_HASH
    )
    body = canonical_payload(payload or {})
    entry = AuditLog(
        prev_hash=prev_hash,
        entry_hash=compute_entry_hash(prev_hash, actor_id, action, resource, body),
        actor_id=actor_id,
        action=action,
        resource=resource,
        payload=body,
    )
    db.add(entry)
    # Flush now so the next append in this transaction sees this entry as its predecessor.
    db.flush()
    return entry

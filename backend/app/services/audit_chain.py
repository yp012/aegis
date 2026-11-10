"""Tamper-evident audit engine: an append-only SHA-256 hash chain with a signed head.

Chain
    Entry ``n`` stores ``entry_hash = SHA256(prev_hash || canonical_json(body))`` where
    ``prev_hash`` is entry ``n-1``'s ``entry_hash`` (64 zeros for the first entry) and ``body``
    is ``{id_seq, actor_id, action, resource, payload, created_at_iso}``. Ids are gapless
    (``1, 2, 3, ...``) and assigned here, so the id is part of what is hashed and a missing id
    is itself evidence of deletion.

Head checkpoint
    The chain alone cannot reveal that its newest entries were removed: what is left is still
    a valid chain. Every append therefore also writes ``audit_checkpoint``, a single row
    holding the head id and hash plus an HMAC-SHA256 over both (key: ``AUDIT_HMAC_SECRET``,
    which the database never sees). Someone with write access to the database but not the
    key can delete or rewrite entries, but cannot produce a matching checkpoint.

Concurrency
    Appends take a transaction-scoped advisory lock before reading the head, so two writers
    can never link to the same predecessor (no forks). The lock is held until the caller's
    transaction ends; the audit row, the checkpoint and the change being audited commit or
    roll back together. Ids are only consumed by committed transactions, so they stay gapless.

Timestamps
    ``created_at`` is taken once in Python (UTC, microseconds) and that same value is both
    stored (TIMESTAMPTZ also has microsecond precision) and hashed as
    ``YYYY-MM-DDTHH:MM:SS.ffffffZ``, so verification reproduces the hash exactly.

Divergence
    If an append finds the head does not match the checkpoint (tail deleted, checkpoint
    removed or forged, rows inserted around this module), it first appends an
    ``audit.chain.divergence`` entry recording what it found, then continues. The evidence
    becomes part of the signed chain instead of being overwritten by the next checkpoint, and
    the API keeps working. ``verify_chain`` reports every such entry.
"""

import enum
import hashlib
import hmac
import json
import logging
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, NamedTuple

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.audit import CHECKPOINT_ROW_ID, GENESIS_HASH, AuditCheckpoint, AuditLog

logger = logging.getLogger(__name__)

# Arbitrary constant key for pg_advisory_xact_lock; released when the transaction ends.
_APPEND_LOCK_ID = 0xA0D17
# Domain separation: this key signs checkpoints and nothing else.
_CHECKPOINT_CONTEXT = "aegis.audit.checkpoint.v1"
_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

DIVERGENCE_ACTION = "audit.chain.divergence"
DEFAULT_BATCH_SIZE = 5000
# Bound on the ids/issues listed in one report; counts are always exact.
MAX_REPORTED = 1000
_CHECKPOINT_HEALTHY = frozenset({"ok", "empty", "not_checked"})


class AuditChainError(Exception):
    """Invalid arguments to the audit engine."""


# --- Canonical encoding ---------------------------------------------------------------------


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
    # Floats are refused: JSONB stores numbers as NUMERIC and may hand back 1e3 as the int
    # 1000, which would re-serialise differently and break the hash.
    if value is None or isinstance(value, bool | int | str):
        return value
    raise TypeError(f"audit payload value of type {type(value).__name__} is not serialisable")


def canonical_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalise ``payload`` to plain JSON types (UUIDs, datetimes and enums become strings)."""
    normalised: dict[str, Any] = _normalise(payload)
    return normalised


def canonical_json(value: Any) -> str:
    """Deterministic ASCII JSON: sorted keys, no whitespace, no NaN/Infinity."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def format_timestamp(moment: datetime) -> str:
    """ISO-8601 UTC with exactly six fractional digits, e.g. ``2026-11-09T12:00:00.000000Z``."""
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("audit timestamps must be timezone-aware")
    return moment.astimezone(UTC).strftime(_TIMESTAMP_FORMAT)


def compute_entry_hash(
    prev_hash: str,
    id_seq: int,
    actor_id: uuid.UUID | None,
    action: str,
    resource: str,
    payload: dict[str, Any],
    created_at_iso: str,
) -> str:
    body = canonical_json(
        {
            "id_seq": id_seq,
            "actor_id": str(actor_id) if actor_id is not None else None,
            "action": action,
            "resource": resource,
            "payload": payload,
            "created_at_iso": created_at_iso,
        }
    )
    return hashlib.sha256((prev_hash + body).encode("ascii")).hexdigest()


# --- Checkpoint signature -------------------------------------------------------------------


def sign_checkpoint(head_id: int, head_hash: str) -> str:
    key = get_settings().audit_hmac_secret.get_secret_value().encode("utf-8")
    message = canonical_json(
        {"context": _CHECKPOINT_CONTEXT, "head_id": head_id, "head_hash": head_hash}
    )
    return hmac.new(key, message.encode("ascii"), hashlib.sha256).hexdigest()


def checkpoint_signature_valid(head_id: int, head_hash: str, signature: str) -> bool:
    return hmac.compare_digest(sign_checkpoint(head_id, head_hash), signature)


# --- Append ---------------------------------------------------------------------------------


class _Link(NamedTuple):
    id: int
    entry_hash: str


class _Checkpoint(NamedTuple):
    head_id: int
    head_hash: str
    signature: str


def _read_checkpoint(db: Session) -> _Checkpoint | None:
    row = db.execute(
        select(AuditCheckpoint.head_id, AuditCheckpoint.head_hash, AuditCheckpoint.signature).where(
            AuditCheckpoint.id == CHECKPOINT_ROW_ID
        )
    ).one_or_none()
    return None if row is None else _Checkpoint(row[0], row[1], row[2])


def _tail_problem(head: _Link | None, checkpoint: _Checkpoint | None) -> str | None:
    """Why the current head disagrees with the signed checkpoint, or None if it agrees."""
    if checkpoint is None:
        return None if head is None else "checkpoint_missing"
    if not checkpoint_signature_valid(
        checkpoint.head_id, checkpoint.head_hash, checkpoint.signature
    ):
        return "checkpoint_invalid"
    if head is None or head.id < checkpoint.head_id:
        return "chain_truncated"
    if head.id > checkpoint.head_id:
        return "unanchored_entries"
    if not hmac.compare_digest(head.entry_hash, checkpoint.head_hash):
        return "head_mismatch"
    return None


def _insert(
    db: Session,
    head: _Link | None,
    actor_id: uuid.UUID | None,
    action: str,
    resource: str,
    payload: dict[str, Any],
) -> AuditLog:
    prev_id, prev_hash = head if head is not None else (0, GENESIS_HASH)
    entry_id = prev_id + 1
    created_at = datetime.now(UTC)
    entry = AuditLog(
        id=entry_id,
        prev_hash=prev_hash,
        entry_hash=compute_entry_hash(
            prev_hash, entry_id, actor_id, action, resource, payload, format_timestamp(created_at)
        ),
        actor_id=actor_id,
        action=action,
        resource=resource,
        payload=payload,
        created_at=created_at,
    )
    db.add(entry)
    # Flush now so the next append in this transaction sees this entry as its predecessor.
    db.flush()
    return entry


def _store_checkpoint(db: Session, entry: AuditLog) -> None:
    values = {
        "head_id": entry.id,
        "head_hash": entry.entry_hash,
        "signature": sign_checkpoint(entry.id, entry.entry_hash),
        "updated_at": entry.created_at,
    }
    stmt = pg_insert(AuditCheckpoint).values(id=CHECKPOINT_ROW_ID, **values)
    db.execute(stmt.on_conflict_do_update(index_elements=[AuditCheckpoint.id], set_=values))


def append(
    db: Session,
    actor_id: uuid.UUID | None,
    action: str,
    resource: str,
    payload: dict[str, Any] | None = None,
) -> AuditLog:
    """Stage one audit entry in ``db``'s current transaction (the caller commits)."""
    body = canonical_payload(payload or {})
    db.execute(select(func.pg_advisory_xact_lock(_APPEND_LOCK_ID)))
    row = db.execute(
        select(AuditLog.id, AuditLog.entry_hash).order_by(AuditLog.id.desc()).limit(1)
    ).one_or_none()
    head = None if row is None else _Link(row[0], row[1])

    checkpoint = _read_checkpoint(db)
    problem = _tail_problem(head, checkpoint)
    if problem is not None:
        logger.critical("audit chain head diverges from its checkpoint: %s", problem)
        divergence = _insert(
            db,
            head,
            None,
            DIVERGENCE_ACTION,
            "audit_logs",
            {
                "reason": problem,
                "checkpoint_head_id": checkpoint.head_id if checkpoint else None,
                "checkpoint_head_hash": checkpoint.head_hash if checkpoint else None,
                "found_head_id": head.id if head else None,
                "found_head_hash": head.entry_hash if head else None,
            },
        )
        head = _Link(divergence.id, divergence.entry_hash)

    entry = _insert(db, head, actor_id, action, resource, body)
    _store_checkpoint(db, entry)
    return entry


# --- Verification ---------------------------------------------------------------------------


class ChainRow(NamedTuple):
    id: int
    prev_hash: str
    entry_hash: str
    actor_id: uuid.UUID | None
    action: str
    resource: str
    payload: dict[str, Any]
    created_at: datetime


@dataclass(frozen=True, slots=True)
class ChainIssue:
    """One finding. ``kind`` is one of: ``gap``, ``broken_link``, ``hash_mismatch``,
    ``divergence_recorded``, ``truncated``, ``checkpoint_missing``, ``checkpoint_invalid``,
    ``checkpoint_mismatch``."""

    id: int | None
    kind: str
    detail: str


@dataclass(slots=True)
class VerificationReport:
    ok: bool
    total: int
    verified: int
    first_broken_id: int | None
    broken_ids: list[int]
    broken_count: int
    issues: list[ChainIssue]
    # ok | empty | missing | invalid_signature | truncated | mismatch | not_checked
    checkpoint: str
    start_id: int | None
    end_id: int | None
    duration_ms: float
    logs_per_second: float


@dataclass
class ChainVerifier:
    """Streaming verifier: feed rows in ascending id order, then call ``finish``.

    Each row is checked three ways: its id follows its predecessor's (no gap), its
    ``prev_hash`` equals the predecessor's *stored* ``entry_hash`` (linkage), and its stored
    ``entry_hash`` matches a hash recomputed from its own content (integrity). Comparing
    against the stored rather than the recomputed predecessor hash keeps a single edited row
    from also flagging its innocent successor.
    """

    prev_id: int = 0
    prev_hash: str = GENESIS_HASH
    total: int = 0
    verified: int = 0
    broken: set[int] = field(default_factory=set)
    issues: list[ChainIssue] = field(default_factory=list)
    issue_count: int = 0

    def flag(self, entry_id: int | None, kind: str, detail: str) -> None:
        if entry_id is not None:
            self.broken.add(entry_id)
        self.issue_count += 1
        if len(self.issues) < MAX_REPORTED:
            self.issues.append(ChainIssue(entry_id, kind, detail))

    def feed(self, row: ChainRow) -> None:
        self.total += 1
        healthy = True
        if row.id != self.prev_id + 1:
            healthy = False
            self.flag(row.id, "gap", f"ids {self.prev_id + 1}..{row.id - 1} are missing")
        if not hmac.compare_digest(row.prev_hash, self.prev_hash):
            healthy = False
            self.flag(row.id, "broken_link", "prev_hash does not match the preceding entry")
        recomputed = compute_entry_hash(
            row.prev_hash,
            row.id,
            row.actor_id,
            row.action,
            row.resource,
            row.payload,
            format_timestamp(row.created_at),
        )
        if not hmac.compare_digest(recomputed, row.entry_hash):
            healthy = False
            self.flag(row.id, "hash_mismatch", "content does not match entry_hash")
        if row.action == DIVERGENCE_ACTION:
            healthy = False
            reason = row.payload.get("reason") if isinstance(row.payload, dict) else None
            self.flag(row.id, "divergence_recorded", f"append found the head diverged: {reason}")
        if healthy:
            self.verified += 1
        self.prev_id, self.prev_hash = row.id, row.entry_hash

    def finish(
        self,
        *,
        checkpoint: str,
        start_id: int | None,
        end_id: int | None,
        elapsed_seconds: float,
    ) -> VerificationReport:
        broken = sorted(self.broken)
        return VerificationReport(
            ok=not broken and self.issue_count == 0 and checkpoint in _CHECKPOINT_HEALTHY,
            total=self.total,
            verified=self.verified,
            first_broken_id=broken[0] if broken else None,
            broken_ids=broken[:MAX_REPORTED],
            broken_count=len(broken),
            issues=self.issues,
            checkpoint=checkpoint,
            start_id=start_id,
            end_id=end_id,
            duration_ms=round(elapsed_seconds * 1000, 3),
            logs_per_second=round(self.total / elapsed_seconds, 1) if elapsed_seconds > 0 else 0.0,
        )


_ROW_COLUMNS = (
    AuditLog.id,
    AuditLog.prev_hash,
    AuditLog.entry_hash,
    AuditLog.actor_id,
    AuditLog.action,
    AuditLog.resource,
    AuditLog.payload,
    AuditLog.created_at,
)


def _check_checkpoint(db: Session, checkpoint: _Checkpoint | None, verifier: ChainVerifier) -> str:
    """Compare the tail against the checkpoint read *before* streaming started.

    Appends commit the row and the checkpoint together and ids only grow, so any row the
    checkpoint names must still exist with the same hash however much was appended since.
    """
    max_id = db.scalar(select(func.max(AuditLog.id))) or 0
    if checkpoint is None:
        if max_id == 0:
            return "empty"
        verifier.flag(None, "checkpoint_missing", "entries exist but no signed head checkpoint")
        return "missing"
    if not checkpoint_signature_valid(
        checkpoint.head_id, checkpoint.head_hash, checkpoint.signature
    ):
        verifier.flag(None, "checkpoint_invalid", "head checkpoint signature does not verify")
        return "invalid_signature"
    if max_id < checkpoint.head_id:
        verifier.flag(
            max_id + 1,
            "truncated",
            f"ids {max_id + 1}..{checkpoint.head_id} named by the checkpoint are missing",
        )
        return "truncated"
    head_hash = db.scalar(select(AuditLog.entry_hash).where(AuditLog.id == checkpoint.head_id))
    if head_hash is None or not hmac.compare_digest(head_hash, checkpoint.head_hash):
        verifier.flag(
            checkpoint.head_id, "checkpoint_mismatch", "entry hash differs from the checkpoint"
        )
        return "mismatch"
    return "ok"


def verify_chain(
    db: Session,
    start_id: int | None = None,
    end_id: int | None = None,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> VerificationReport:
    """Verify entries ``start_id..end_id`` (inclusive; default: the whole chain).

    Rows are streamed with keyset pagination, ``batch_size`` at a time, so memory stays flat
    however long the chain is. The head checkpoint is checked whenever the range runs to the
    current end of the chain (``end_id`` is None).
    """
    if start_id is not None and start_id < 1:
        raise AuditChainError("start_id must be >= 1")
    if end_id is not None and end_id < (start_id or 1):
        raise AuditChainError("end_id must be >= start_id")
    if batch_size < 1:
        raise AuditChainError("batch_size must be >= 1")

    started = time.perf_counter()
    # Read first: everything committed before it is then guaranteed to be visible below.
    checkpoint = _read_checkpoint(db) if end_id is None else None

    verifier = ChainVerifier()
    if start_id is not None and start_id > 1:
        before = db.execute(
            select(AuditLog.id, AuditLog.entry_hash)
            .where(AuditLog.id < start_id)
            .order_by(AuditLog.id.desc())
            .limit(1)
        ).one_or_none()
        if before is not None:
            verifier.prev_id, verifier.prev_hash = before[0], before[1]

    cursor = (start_id or 1) - 1
    while True:
        stmt = select(*_ROW_COLUMNS).where(AuditLog.id > cursor)
        if end_id is not None:
            stmt = stmt.where(AuditLog.id <= end_id)
        batch: Sequence[Any] = db.execute(stmt.order_by(AuditLog.id).limit(batch_size)).all()
        for row in batch:
            verifier.feed(ChainRow(*row))
        if len(batch) < batch_size:
            break
        cursor = batch[-1][0]

    status = "not_checked" if end_id is not None else _check_checkpoint(db, checkpoint, verifier)
    return verifier.finish(
        checkpoint=status,
        start_id=start_id,
        end_id=end_id,
        elapsed_seconds=time.perf_counter() - started,
    )

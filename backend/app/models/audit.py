"""ORM models: audit log (append-only SHA-256 hash chain) and its signed head checkpoint.

Immutability is enforced in the database by the ``audit_log_immutable`` trigger
(see the initial Alembic migration), which rejects UPDATE, DELETE and TRUNCATE.
Rows are written only through ``app.services.audit_chain``, which assigns the gapless ids.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, ForeignKey, SmallInteger, String, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.types import CreatedAt

GENESIS_HASH = "0" * 64
CHECKPOINT_ROW_ID = 1


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        CheckConstraint("prev_hash ~ '^[0-9a-f]{64}$'", name="prev_hash_is_sha256_hex"),
        CheckConstraint("entry_hash ~ '^[0-9a-f]{64}$'", name="entry_hash_is_sha256_hex"),
        CheckConstraint("id > 0", name="id_positive"),
    )

    # Gapless chain position, assigned by audit_chain.append under its advisory lock (no
    # sequence: one would leave gaps on rollback and hide real deletions).
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    # RESTRICT: an actor with audit history cannot be hard-deleted (deactivate instead).
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource: Mapped[str] = mapped_column(String(255), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[CreatedAt]


class AuditCheckpoint(Base):
    """Singleton row: the newest entry's id and hash, HMAC-signed with AUDIT_HMAC_SECRET.

    Updated in the same transaction as every append, so it always names the committed head.
    Lets verification detect deletion of the newest entries, which the chain alone cannot.
    """

    __tablename__ = "audit_checkpoint"
    __table_args__ = (
        CheckConstraint(f"id = {CHECKPOINT_ROW_ID}", name="singleton"),
        CheckConstraint("head_id > 0", name="head_id_positive"),
        CheckConstraint("head_hash ~ '^[0-9a-f]{64}$'", name="head_hash_is_sha256_hex"),
        CheckConstraint("signature ~ '^[0-9a-f]{64}$'", name="signature_is_hmac_sha256_hex"),
    )

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, autoincrement=False)
    head_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    head_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(nullable=False)

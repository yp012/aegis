"""ORM model: audit log (append-only SHA-256 hash chain).

Immutability is enforced in the database by the ``audit_log_immutable`` trigger
(see the initial Alembic migration), which rejects UPDATE, DELETE and TRUNCATE.
"""

import uuid
from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, ForeignKey, String, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.types import CreatedAt

GENESIS_HASH = "0" * 64


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        CheckConstraint("prev_hash ~ '^[0-9a-f]{64}$'", name="prev_hash_is_sha256_hex"),
        CheckConstraint("entry_hash ~ '^[0-9a-f]{64}$'", name="entry_hash_is_sha256_hex"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
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

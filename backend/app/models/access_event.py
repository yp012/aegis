"""ORM model: access event (every zone entry decision, granted or denied)."""

import uuid

from sqlalchemy import ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.types import CreatedAt, UUIDPrimaryKey, pg_enum
from app.models.enums import AccessResult, SubjectType


class AccessEvent(Base):
    __tablename__ = "access_events"
    __table_args__ = (Index("ix_access_events_subject", "subject_type", "subject_id"),)

    id: Mapped[UUIDPrimaryKey]
    subject_type: Mapped[SubjectType] = mapped_column(
        pg_enum(SubjectType, "subject_type"), nullable=False
    )
    # Polymorphic reference (users.id or visitors.id), so no foreign key.
    subject_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    # SET NULL keeps the historical event if a zone is later removed.
    zone_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("zones.id", ondelete="SET NULL"), nullable=True, index=True
    )
    result: Mapped[AccessResult] = mapped_column(
        pg_enum(AccessResult, "access_result"), nullable=False
    )
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    created_at: Mapped[CreatedAt] = mapped_column(index=True)

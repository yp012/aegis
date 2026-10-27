"""ORM model: zone access grant."""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.types import CreatedAt, UUIDPrimaryKey


class ZoneAccessGrant(Base):
    """Explicit, time-bound permission for exactly one subject (user or visitor) on a zone."""

    __tablename__ = "zone_access_grants"
    __table_args__ = (
        CheckConstraint(
            "(user_id IS NOT NULL) <> (visitor_id IS NOT NULL)",
            name="exactly_one_subject",
        ),
        CheckConstraint("expires_at > created_at", name="expires_after_created"),
        Index("ix_zone_access_grants_user_zone", "user_id", "zone_id"),
        Index("ix_zone_access_grants_visitor_zone", "visitor_id", "zone_id"),
    )

    id: Mapped[UUIDPrimaryKey]
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=True
    )
    visitor_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("visitors.id", ondelete="CASCADE"), nullable=True
    )
    zone_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("zones.id", ondelete="CASCADE"), nullable=False, index=True
    )
    granted_by: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[CreatedAt]

    def is_valid_at(self, moment: datetime) -> bool:
        """True if the grant is neither revoked nor expired at ``moment`` (tz-aware)."""
        if moment.tzinfo is None:
            raise ValueError("moment must be timezone-aware")
        if self.revoked_at is not None and self.revoked_at <= moment:
            return False
        return moment < self.expires_at

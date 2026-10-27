"""ORM model: badge."""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, String, false, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.types import UUIDPrimaryKey


class Badge(Base):
    """Server-side record of an issued visitor badge; ``jti`` binds it to the signed QR payload."""

    __tablename__ = "badges"
    __table_args__ = (CheckConstraint("expires_at > issued_at", name="expires_after_issued"),)

    id: Mapped[UUIDPrimaryKey]
    visitor_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("visitors.id", ondelete="CASCADE"), nullable=False, index=True
    )
    jti: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(nullable=False, server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    revoked: Mapped[bool] = mapped_column(default=False, server_default=false(), nullable=False)
    last_scanned_at: Mapped[datetime | None] = mapped_column(nullable=True)

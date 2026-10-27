"""ORM model: zone."""

from sqlalchemy import CheckConstraint, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.types import UUIDPrimaryKey, pg_enum
from app.models.enums import Clearance


class Zone(Base):
    __tablename__ = "zones"
    __table_args__ = (
        CheckConstraint("capacity > 0", name="capacity_positive"),
        CheckConstraint(
            "current_occupancy >= 0 AND current_occupancy <= capacity",
            name="occupancy_within_capacity",
        ),
    )

    id: Mapped[UUIDPrimaryKey]
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", server_default="", nullable=False)
    min_clearance: Mapped[Clearance] = mapped_column(
        pg_enum(Clearance, "clearance"), nullable=False
    )
    capacity: Mapped[int] = mapped_column(nullable=False)
    current_occupancy: Mapped[int] = mapped_column(default=0, server_default="0", nullable=False)

    def __repr__(self) -> str:
        return f"<Zone id={self.id} name={self.name!r} min_clearance={self.min_clearance}>"

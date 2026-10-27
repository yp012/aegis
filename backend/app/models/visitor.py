"""ORM model: visitor."""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.types import CreatedAt, UUIDPrimaryKey, pg_enum
from app.models.enums import Clearance, VisitorStatus, VisitorType


class Visitor(Base):
    __tablename__ = "visitors"
    __table_args__ = (CheckConstraint("visit_end > visit_start", name="visit_window_ordered"),)

    id: Mapped[UUIDPrimaryKey]
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    company: Mapped[str | None] = mapped_column(String(200), nullable=True)
    visitor_type: Mapped[VisitorType] = mapped_column(
        pg_enum(VisitorType, "visitor_type"), nullable=False
    )
    host_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    clearance: Mapped[Clearance] = mapped_column(
        pg_enum(Clearance, "clearance"),
        default=Clearance.Reliability,
        server_default=Clearance.Reliability.name,
        nullable=False,
    )
    status: Mapped[VisitorStatus] = mapped_column(
        pg_enum(VisitorStatus, "visitor_status"),
        default=VisitorStatus.Pending,
        server_default=VisitorStatus.Pending.name,
        nullable=False,
        index=True,
    )
    visit_start: Mapped[datetime] = mapped_column(nullable=False)
    visit_end: Mapped[datetime] = mapped_column(nullable=False)
    created_at: Mapped[CreatedAt]

    def __repr__(self) -> str:
        return f"<Visitor id={self.id} type={self.visitor_type} status={self.status}>"

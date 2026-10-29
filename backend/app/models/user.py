"""ORM model: user."""

from datetime import datetime

from sqlalchemy import CheckConstraint, String, Text, false, true
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.types import CreatedAt, UUIDPrimaryKey, pg_enum
from app.models.enums import Clearance, Role


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("failed_login_count >= 0", name="failed_login_count_non_negative"),
        CheckConstraint("email = lower(email)", name="email_lowercase"),
        CheckConstraint(
            "NOT mfa_enabled OR mfa_secret_encrypted IS NOT NULL",
            name="mfa_enabled_requires_secret",
        ),
    )

    id: Mapped[UUIDPrimaryKey]
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[Role] = mapped_column(pg_enum(Role, "role"), nullable=False)
    clearance: Mapped[Clearance] = mapped_column(pg_enum(Clearance, "clearance"), nullable=False)
    is_active: Mapped[bool] = mapped_column(default=True, server_default=true(), nullable=False)
    mfa_enabled: Mapped[bool] = mapped_column(default=False, server_default=false(), nullable=False)
    mfa_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    failed_login_count: Mapped[int] = mapped_column(default=0, server_default="0", nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[CreatedAt]

    def __repr__(self) -> str:
        return f"<User id={self.id} role={self.role} clearance={self.clearance}>"

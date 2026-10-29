"""users email lowercase

Emails are normalised to lowercase by the auth service before every insert and lookup. This
CHECK makes that a database guarantee, so the unique index on `email` is effectively
case-insensitive and no code path can create `Alice@x.io` next to `alice@x.io`.

Revision ID: 495072b64b57
Revises: b854d7ed4697
Create Date: 2026-10-29 12:00:00.000000+00:00

"""
from collections.abc import Sequence

from alembic import op

revision: str = '495072b64b57'
down_revision: str | None = 'b854d7ed4697'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_check_constraint('email_lowercase', 'users', 'email = lower(email)')


def downgrade() -> None:
    op.drop_constraint(op.f('ck_users_email_lowercase'), 'users', type_='check')

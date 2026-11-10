"""audit gapless ids and signed head checkpoint

The tamper-evident audit engine (app/services/audit_chain.py) hashes each entry's id and
assigns ids itself, gapless, under its advisory lock. The `audit_logs.id` sequence is dropped
so nothing else can hand out ids: with a sequence, rolled-back transactions would leave gaps
that look exactly like deleted entries. `id > 0` keeps hand-written ids sane.

`audit_checkpoint` is a single row with the chain head's id and hash plus an HMAC-SHA256
signature (key: AUDIT_HMAC_SECRET, never stored in the database). It is updated in the same
transaction as every append, which is what lets verification detect deletion of the newest
entries. The app role may read, insert and update it, but not delete it.

Entries written by the previous engine used a different hash format and cannot be verified,
so the upgrade refuses to run on a database that already has audit entries.

Revision ID: 7c3e9a1f2b64
Revises: 495072b64b57
Create Date: 2026-11-09 12:00:00.000000+00:00

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '7c3e9a1f2b64'
down_revision: str | None = '495072b64b57'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = 'aegis_app'
ID_SEQUENCE = 'audit_logs_id_seq'


def upgrade() -> None:
    existing = op.get_bind().execute(sa.text('SELECT count(*) FROM audit_logs')).scalar_one()
    if existing:
        raise RuntimeError(
            f'audit_logs already holds {existing} entries in the pre-checkpoint hash format, '
            'which the new engine cannot verify. This revision only supports empty audit '
            'trails: recreate the development database (docker compose down -v) and migrate.'
        )

    op.execute('ALTER TABLE audit_logs ALTER COLUMN id DROP DEFAULT')
    op.execute(f'DROP SEQUENCE IF EXISTS {ID_SEQUENCE}')
    op.create_check_constraint('id_positive', 'audit_logs', 'id > 0')

    op.create_table('audit_checkpoint',
    sa.Column('id', sa.SmallInteger(), autoincrement=False, nullable=False),
    sa.Column('head_id', sa.BigInteger(), nullable=False),
    sa.Column('head_hash', sa.String(length=64), nullable=False),
    sa.Column('signature', sa.String(length=64), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint('id = 1', name=op.f('ck_audit_checkpoint_singleton')),
    sa.CheckConstraint('head_id > 0', name=op.f('ck_audit_checkpoint_head_id_positive')),
    sa.CheckConstraint("head_hash ~ '^[0-9a-f]{64}$'", name=op.f('ck_audit_checkpoint_head_hash_is_sha256_hex')),
    sa.CheckConstraint("signature ~ '^[0-9a-f]{64}$'", name=op.f('ck_audit_checkpoint_signature_is_hmac_sha256_hex')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_checkpoint'))
    )
    # Default privileges (restricted app role migration) granted full DML on the new table.
    op.execute(f'REVOKE DELETE, TRUNCATE ON audit_checkpoint FROM {APP_ROLE}')


def downgrade() -> None:
    op.drop_table('audit_checkpoint')
    op.drop_constraint(op.f('ck_audit_logs_id_positive'), 'audit_logs', type_='check')
    op.execute(f'CREATE SEQUENCE {ID_SEQUENCE} AS bigint OWNED BY audit_logs.id')
    op.execute(
        f"SELECT setval('{ID_SEQUENCE}', COALESCE(max(id), 0) + 1, false) FROM audit_logs"
    )
    op.execute(f"ALTER TABLE audit_logs ALTER COLUMN id SET DEFAULT nextval('{ID_SEQUENCE}')")
    op.execute(f'GRANT USAGE ON SEQUENCE {ID_SEQUENCE} TO {APP_ROLE}')

"""restricted app role

Creates the `aegis_app` login role the API connects as. It is not a superuser, owns no
objects, and holds only DML privileges. On `audit_logs` it may only SELECT and INSERT, so a
stolen app credential can neither mutate the audit trail nor bypass its trigger (that would
need ownership or superuser: DISABLE TRIGGER, DROP, session_replication_role).

The password comes from APP_DB_PASSWORD and is sent to the server only as a SCRAM-SHA-256
verifier computed client-side. Re-running the upgrade on a cluster where the role already
exists (roles are cluster-wide) resets its attributes and password to the values below.

Revision ID: b854d7ed4697
Revises: cb65e740a2cf
Create Date: 2026-10-29 10:00:00.000000+00:00

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from app.core.config import get_migration_settings
from app.db.scram import VERIFIER_PATTERN, scram_sha256_verifier

revision: str = 'b854d7ed4697'
down_revision: str | None = 'cb65e740a2cf'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = 'aegis_app'

CREATE_ROLE_IF_MISSING = f"""
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
        CREATE ROLE {APP_ROLE};
    END IF;
END
$$;
"""

GRANT_CONNECT = f"""
DO $$
BEGIN
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO {APP_ROLE}', current_database());
END
$$;
"""

PRIVILEGES = (
    f"GRANT USAGE ON SCHEMA public TO {APP_ROLE}",
    f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {APP_ROLE}",
    f"GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {APP_ROLE}",
    # The audit trail is append-only for the app as well as by trigger.
    f"REVOKE UPDATE, DELETE ON audit_logs FROM {APP_ROLE}",
    # Migration bookkeeping is the owner's business.
    f"REVOKE ALL ON alembic_version FROM {APP_ROLE}",
    # Tables and sequences created by later migrations (run as this same owner) get the same
    # DML grants automatically. A new append-only table must REVOKE explicitly, as above.
    f"ALTER DEFAULT PRIVILEGES IN SCHEMA public "
    f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {APP_ROLE}",
    f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE ON SEQUENCES TO {APP_ROLE}",
)

DROP_ROLE_IF_UNUSED = f"""
DO $$
BEGIN
    DROP ROLE IF EXISTS {APP_ROLE};
EXCEPTION WHEN dependent_objects_still_exist THEN
    RAISE NOTICE 'role {APP_ROLE} still has privileges in another database; not dropped';
END
$$;
"""


def upgrade() -> None:
    password = get_migration_settings().app_db_password.get_secret_value()
    verifier = scram_sha256_verifier(password)
    # The verifier alphabet (base64, '$', ':') cannot contain a quote, so inlining is safe.
    if VERIFIER_PATTERN.fullmatch(verifier) is None:
        raise RuntimeError("unexpected SCRAM verifier format")

    # text() would read the verifier's ':' separators as bind parameters, so escape them.
    escaped = verifier.replace(':', r'\:')

    op.execute(CREATE_ROLE_IF_MISSING)
    op.execute(
        sa.text(
            f"ALTER ROLE {APP_ROLE} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
            f"NOREPLICATION NOBYPASSRLS PASSWORD '{escaped}'"
        )
    )
    op.execute(GRANT_CONNECT)
    for statement in PRIVILEGES:
        op.execute(statement)


def downgrade() -> None:
    # DROP OWNED revokes every privilege and default privilege the role holds in this
    # database (it owns no objects, so nothing is dropped).
    op.execute(
        f"DO $$ BEGIN IF EXISTS (SELECT FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN "
        f"DROP OWNED BY {APP_ROLE}; END IF; END $$;"
    )
    op.execute(DROP_ROLE_IF_UNUSED)

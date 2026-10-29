"""Alembic migration environment wired to application settings and metadata."""

from logging.config import fileConfig

from sqlalchemy import Connection, engine_from_config, pool

import app.models  # noqa: F401  (registers all models on Base.metadata)
from alembic import context
from app.core.config import get_migration_settings
from app.db.base import Base

config = context.config
# Migrations run as the schema owner (DATABASE_URL); the API uses APP_DATABASE_URL.
config.set_main_option("sqlalchemy.url", get_migration_settings().database_url.replace("%", "%%"))

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _run_with_connection(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    # Callers (e.g. integration tests) may supply their own connection.
    provided = config.attributes.get("connection")
    if provided is not None:
        _run_with_connection(provided)
        return

    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        _run_with_connection(connection)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

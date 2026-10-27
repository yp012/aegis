"""Reusable column types and annotated mappings for ORM models."""

import enum
import uuid
from datetime import datetime
from typing import Annotated

from sqlalchemy import Enum, func, text
from sqlalchemy.orm import mapped_column

UUIDPrimaryKey = Annotated[
    uuid.UUID,
    mapped_column(primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")),
]

CreatedAt = Annotated[
    datetime,
    mapped_column(nullable=False, server_default=func.now()),
]


def pg_enum(enum_cls: type[enum.Enum], name: str) -> Enum:
    """Native PostgreSQL enum whose labels are the Python member names."""
    return Enum(
        enum_cls,
        name=name,
        native_enum=True,
        create_constraint=False,
        validate_strings=True,
    )

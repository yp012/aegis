"""Pydantic schemas: user."""

import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    PlainSerializer,
    StringConstraints,
    WithJsonSchema,
)

from app.models.enums import Clearance, Role


def _parse_clearance(value: Any) -> Clearance:
    if isinstance(value, Clearance):
        return value
    if isinstance(value, str):
        return Clearance.parse(value)
    raise ValueError("clearance must be one of " + ", ".join(c.name for c in Clearance))


# Clearance travels over the API by its canonical label ("Top_Secret"), never as a bare int.
ClearanceLabel = Annotated[
    Clearance,
    BeforeValidator(_parse_clearance),
    PlainSerializer(lambda c: c.name, return_type=str),
    WithJsonSchema({"type": "string", "enum": [c.name for c in Clearance]}),
]


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    full_name: str
    role: Role
    clearance: ClearanceLabel
    is_active: bool
    mfa_enabled: bool
    created_at: datetime


class UserUpdate(BaseModel):
    """Admin-only partial update. Omitted fields are left unchanged."""

    model_config = ConfigDict(extra="forbid")

    full_name: (
        Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
        | None
    ) = None
    role: Role | None = None
    clearance: ClearanceLabel | None = None
    is_active: bool | None = None

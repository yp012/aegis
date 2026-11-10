"""Pydantic schemas: zone, zone access grant, access attempt."""

import uuid
from datetime import datetime
from typing import Annotated, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

from app.models.enums import AccessResult, SubjectType
from app.schemas.user import ClearanceLabel
from app.services.policy_engine import Direction

ZoneName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]
Description = Annotated[str, Field(max_length=2000)]
Capacity = Annotated[int, Field(ge=1, le=100_000)]


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ZoneCreate(_Request):
    name: ZoneName
    description: Description = ""
    min_clearance: ClearanceLabel
    capacity: Capacity


class ZoneUpdate(_Request):
    name: ZoneName | None = None
    description: Description | None = None
    min_clearance: ClearanceLabel | None = None
    capacity: Capacity | None = None


class ZoneRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str
    min_clearance: ClearanceLabel
    capacity: int
    current_occupancy: int


class GrantCreate(_Request):
    """Grant a zone to exactly one subject: a user or a visitor."""

    user_id: uuid.UUID | None = None
    visitor_id: uuid.UUID | None = None
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def _exactly_one_subject(self) -> Self:
        if (self.user_id is None) == (self.visitor_id is None):
            raise ValueError("provide exactly one of user_id or visitor_id")
        return self

    def subject(self) -> tuple[SubjectType, uuid.UUID]:
        if self.user_id is not None:
            return SubjectType.User, self.user_id
        if self.visitor_id is not None:
            return SubjectType.Visitor, self.visitor_id
        raise ValueError("grant has no subject")


class GrantRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    zone_id: uuid.UUID
    user_id: uuid.UUID | None
    visitor_id: uuid.UUID | None
    granted_by: uuid.UUID
    expires_at: datetime
    revoked_at: datetime | None
    created_at: datetime


class AccessAttemptRequest(_Request):
    """An entry or exit attempt. With no ``subject_id`` the caller is the subject."""

    subject_type: SubjectType = SubjectType.User
    subject_id: uuid.UUID | None = None
    direction: Direction = Direction.Entry


class AccessAttemptResponse(BaseModel):
    event_id: uuid.UUID
    zone_id: uuid.UUID
    subject_type: SubjectType
    subject_id: uuid.UUID
    direction: Direction
    result: AccessResult
    reason: str
    current_occupancy: int

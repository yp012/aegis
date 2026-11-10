"""Pydantic schemas: audit."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class AuditLogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    prev_hash: str
    entry_hash: str
    actor_id: uuid.UUID | None
    action: str
    resource: str
    payload: dict[str, Any]
    created_at: datetime


class AuditLogPage(BaseModel):
    items: list[AuditLogRead]
    total: int
    page: int
    page_size: int


class ChainIssueRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int | None
    kind: str
    detail: str


class VerificationReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ok: bool
    total: int
    verified: int
    first_broken_id: int | None
    broken_ids: list[int]
    broken_count: int
    issues: list[ChainIssueRead]
    checkpoint: str
    start_id: int | None
    end_id: int | None
    duration_ms: float
    logs_per_second: float
    # Id of the ``audit.verify`` entry that records this run.
    audit_entry_id: int

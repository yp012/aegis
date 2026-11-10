"""API v1 routes: audit.

Admin and SecurityOfficer only. ``GET /audit/logs`` pages through the trail, newest first.
``GET /audit/verify`` runs a full (or ranged) integrity check of the hash chain and its signed
head checkpoint, then appends an ``audit.verify`` entry recording who ran it and what it
found, so checks of the trail are themselves part of the trail.
"""

from dataclasses import asdict
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select

from app.core.deps import DbSession, require_roles
from app.models.audit import AuditLog
from app.models.enums import Role
from app.models.user import User
from app.schemas.audit import AuditLogPage, AuditLogRead, VerificationReportRead
from app.services import audit_chain

router = APIRouter(prefix="/audit", tags=["audit"])

Auditor = Annotated[User, Depends(require_roles(Role.Admin, Role.SecurityOfficer))]

MAX_PAGE_SIZE = 200


@router.get("/logs", response_model=AuditLogPage)
def list_logs(
    _: Auditor,
    db: DbSession,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
) -> AuditLogPage:
    total = db.scalar(select(func.count()).select_from(AuditLog)) or 0
    rows = db.scalars(
        select(AuditLog)
        .order_by(AuditLog.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    return AuditLogPage(
        items=[AuditLogRead.model_validate(row) for row in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/verify", response_model=VerificationReportRead)
def verify(
    actor: Auditor,
    db: DbSession,
    start_id: Annotated[int | None, Query(ge=1)] = None,
    end_id: Annotated[int | None, Query(ge=1)] = None,
) -> VerificationReportRead:
    try:
        report = audit_chain.verify_chain(db, start_id=start_id, end_id=end_id)
    except audit_chain.AuditChainError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from None
    entry = audit_chain.append(
        db,
        actor.id,
        "audit.verify",
        "audit_logs",
        {
            "ok": report.ok,
            "start_id": start_id,
            "end_id": end_id,
            "total": report.total,
            "verified": report.verified,
            "broken_count": report.broken_count,
            "first_broken_id": report.first_broken_id,
            "checkpoint": report.checkpoint,
            # Floats are not hashable payload values; whole milliseconds are enough here.
            "duration_ms": int(report.duration_ms),
        },
    )
    db.commit()
    return VerificationReportRead.model_validate({**asdict(report), "audit_entry_id": entry.id})

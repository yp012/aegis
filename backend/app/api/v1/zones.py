"""API v1 routes: zones, zone access grants and access attempts.

- Any authenticated user may list and read zones.
- Admin creates, updates and deletes zones.
- Admin or SecurityOfficer provisions and revokes grants. Provisioning is refused (422, with
  the policy reason) when the subject's clearance is below the zone's minimum, so a grant
  that could never be honoured is never written.
- ``POST /zones/{id}/access-attempt`` runs the policy engine, records an ``AccessEvent``
  (Granted or Denied, with the reason and client IP) and updates occupancy on success.
  Personnel may only attempt access as themselves; Admin and SecurityOfficer may submit
  attempts for any user or visitor (e.g. a guard scanning someone at a door).

Every mutation and every access decision is appended to the audit log in the same
transaction as the change it describes.
"""

import ipaddress
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.deps import CurrentUser, DbSession, require_roles
from app.core.rate_limit import client_ip
from app.models.access_event import AccessEvent
from app.models.enums import AccessResult, Role, SubjectType
from app.models.grant import ZoneAccessGrant
from app.models.user import User
from app.models.visitor import Visitor
from app.models.zone import Zone
from app.schemas.zone import (
    AccessAttemptRequest,
    AccessAttemptResponse,
    GrantCreate,
    GrantRead,
    ZoneCreate,
    ZoneRead,
    ZoneUpdate,
)
from app.services import audit_chain
from app.services.policy_engine import (
    Direction,
    Reason,
    Subject,
    evaluate_zone_access,
)

router = APIRouter(prefix="/zones", tags=["zones"])

ZONE_NOT_FOUND = "Zone not found"
GRANT_NOT_FOUND = "Grant not found"
ZONE_NAME_TAKEN = "Zone name already exists"

AdminUser = Annotated[User, Depends(require_roles(Role.Admin))]
Provisioner = Annotated[User, Depends(require_roles(Role.Admin, Role.SecurityOfficer))]


def _zone_or_404(db: Session, zone_id: uuid.UUID, *, lock: bool = False) -> Zone:
    zone = db.get(Zone, zone_id, with_for_update=lock)
    if zone is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, ZONE_NOT_FOUND)
    return zone


def _zone_snapshot(zone: Zone) -> dict[str, Any]:
    return {
        "name": zone.name,
        "description": zone.description,
        "min_clearance": zone.min_clearance,
        "capacity": zone.capacity,
    }


def _inet_or_none(value: str) -> str | None:
    """The INET column only takes real addresses (the test client's peer is "testclient")."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


# --- Zone CRUD ----------------------------------------------------------------------------


@router.get("", response_model=list[ZoneRead])
def list_zones(_: CurrentUser, db: DbSession) -> list[Zone]:
    return list(db.scalars(select(Zone).order_by(Zone.name)))


@router.get("/{zone_id}", response_model=ZoneRead)
def get_zone(zone_id: uuid.UUID, _: CurrentUser, db: DbSession) -> Zone:
    return _zone_or_404(db, zone_id)


@router.post("", response_model=ZoneRead, status_code=status.HTTP_201_CREATED)
def create_zone(payload: ZoneCreate, actor: AdminUser, db: DbSession) -> Zone:
    if db.scalar(select(Zone.id).where(Zone.name == payload.name)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, ZONE_NAME_TAKEN)
    zone = Zone(**payload.model_dump(), current_occupancy=0)
    db.add(zone)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, ZONE_NAME_TAKEN) from None
    audit_chain.append(db, actor.id, "zone.create", f"zones/{zone.id}", _zone_snapshot(zone))
    db.commit()
    return zone


@router.patch("/{zone_id}", response_model=ZoneRead)
def update_zone(zone_id: uuid.UUID, payload: ZoneUpdate, actor: AdminUser, db: DbSession) -> Zone:
    zone = _zone_or_404(db, zone_id, lock=True)
    before = _zone_snapshot(zone)
    updates = payload.model_dump(exclude_none=True)
    if "capacity" in updates and updates["capacity"] < zone.current_occupancy:
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Capacity cannot be set below current occupancy"
        )
    if "name" in updates and updates["name"] != zone.name:
        clash = db.scalar(select(Zone.id).where(Zone.name == updates["name"], Zone.id != zone.id))
        if clash is not None:
            db.rollback()
            raise HTTPException(status.HTTP_409_CONFLICT, ZONE_NAME_TAKEN)
    for field, value in updates.items():
        setattr(zone, field, value)
    after = _zone_snapshot(zone)
    changes = {k: {"from": before[k], "to": after[k]} for k in before if before[k] != after[k]}
    if not changes:
        db.rollback()
        return zone
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, ZONE_NAME_TAKEN) from None
    audit_chain.append(db, actor.id, "zone.update", f"zones/{zone.id}", {"changes": changes})
    db.commit()
    return zone


@router.delete("/{zone_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_zone(zone_id: uuid.UUID, actor: AdminUser, db: DbSession) -> Response:
    zone = _zone_or_404(db, zone_id, lock=True)
    snapshot = _zone_snapshot(zone)
    # Grants cascade; historical access events keep their row with zone_id set to NULL.
    db.delete(zone)
    audit_chain.append(db, actor.id, "zone.delete", f"zones/{zone_id}", snapshot)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Grants -------------------------------------------------------------------------------


def _load_subject(db: Session, subject_type: SubjectType, subject_id: uuid.UUID) -> Subject | None:
    if subject_type == SubjectType.User:
        return db.get(User, subject_id)
    return db.get(Visitor, subject_id)


@router.post("/{zone_id}/grant", response_model=GrantRead, status_code=status.HTTP_201_CREATED)
def create_grant(
    zone_id: uuid.UUID, payload: GrantCreate, actor: Provisioner, db: DbSession
) -> ZoneAccessGrant:
    zone = _zone_or_404(db, zone_id)
    subject_type, subject_id = payload.subject()
    subject = _load_subject(db, subject_type, subject_id)
    if subject is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{subject_type.value} not found")
    if payload.expires_at <= datetime.now(UTC):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "expires_at must be in the future"
        )

    subject_ref = {"subject_type": subject_type, "subject_id": subject_id}
    if not subject.clearance.satisfies(zone.min_clearance):
        # The refusal is itself security-relevant (attempted over-provisioning): record it.
        audit_chain.append(
            db,
            actor.id,
            "zone.grant.refused",
            f"zones/{zone.id}",
            {
                **subject_ref,
                "reason": Reason.INSUFFICIENT_CLEARANCE,
                "subject_clearance": subject.clearance,
                "zone_min_clearance": zone.min_clearance,
            },
        )
        db.commit()
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            {
                "reason": Reason.INSUFFICIENT_CLEARANCE.value,
                "message": (
                    f"{subject_type.value} clearance {subject.clearance.name} is below the "
                    f"zone minimum {zone.min_clearance.name}"
                ),
            },
        )

    grant = ZoneAccessGrant(
        zone_id=zone.id,
        user_id=payload.user_id,
        visitor_id=payload.visitor_id,
        granted_by=actor.id,
        expires_at=payload.expires_at,
    )
    db.add(grant)
    db.flush()
    audit_chain.append(
        db,
        actor.id,
        "zone.grant.create",
        f"zones/{zone.id}/grants/{grant.id}",
        {**subject_ref, "expires_at": grant.expires_at},
    )
    db.commit()
    db.refresh(grant)
    return grant


@router.get("/{zone_id}/grants", response_model=list[GrantRead])
def list_grants(zone_id: uuid.UUID, _: Provisioner, db: DbSession) -> list[ZoneAccessGrant]:
    _zone_or_404(db, zone_id)
    return list(
        db.scalars(
            select(ZoneAccessGrant)
            .where(ZoneAccessGrant.zone_id == zone_id)
            .order_by(ZoneAccessGrant.created_at.desc(), ZoneAccessGrant.id)
        )
    )


@router.post("/{zone_id}/grants/{grant_id}/revoke", response_model=GrantRead)
def revoke_grant(
    zone_id: uuid.UUID, grant_id: uuid.UUID, actor: Provisioner, db: DbSession
) -> ZoneAccessGrant:
    grant = db.get(ZoneAccessGrant, grant_id, with_for_update=True)
    if grant is None or grant.zone_id != zone_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, GRANT_NOT_FOUND)
    if grant.revoked_at is not None:
        db.rollback()
        return grant
    grant.revoked_at = datetime.now(UTC)
    audit_chain.append(
        db,
        actor.id,
        "zone.grant.revoke",
        f"zones/{zone_id}/grants/{grant.id}",
        {"user_id": grant.user_id, "visitor_id": grant.visitor_id},
    )
    db.commit()
    return grant


# --- Access attempts ----------------------------------------------------------------------


def _best_grant(
    db: Session, zone_id: uuid.UUID, subject_type: SubjectType, subject_id: uuid.UUID, now: datetime
) -> ZoneAccessGrant | None:
    """A currently valid grant if one exists, else the newest one (so a denial can say
    *why*: revoked or expired), else None."""
    column = (
        ZoneAccessGrant.user_id if subject_type == SubjectType.User else ZoneAccessGrant.visitor_id
    )
    grants = list(
        db.scalars(
            select(ZoneAccessGrant)
            .where(ZoneAccessGrant.zone_id == zone_id, column == subject_id)
            .order_by(ZoneAccessGrant.created_at.desc(), ZoneAccessGrant.id)
        )
    )
    return next((g for g in grants if g.is_valid_at(now)), grants[0] if grants else None)


@router.post("/{zone_id}/access-attempt", response_model=AccessAttemptResponse)
def access_attempt(
    zone_id: uuid.UUID,
    payload: AccessAttemptRequest,
    request: Request,
    actor: CurrentUser,
    db: DbSession,
) -> AccessAttemptResponse:
    subject_type = payload.subject_type
    subject_id = payload.subject_id
    if subject_id is None:
        if subject_type != SubjectType.User:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, "subject_id is required for visitors"
            )
        subject_id = actor.id
    if actor.role == Role.Personnel and (
        subject_type != SubjectType.User or subject_id != actor.id
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Personnel may only badge in as themselves")

    # Row lock: concurrent entries to the same zone are serialised, so the capacity check
    # and the occupancy increment cannot race past the limit.
    zone = _zone_or_404(db, zone_id, lock=True)
    now = datetime.now(UTC)
    subject = _load_subject(db, subject_type, subject_id)
    grant = _best_grant(db, zone.id, subject_type, subject_id, now)
    decision = evaluate_zone_access(subject, zone, grant, now, payload.direction)

    if decision.allowed:
        if payload.direction == Direction.Entry:
            zone.current_occupancy += 1
        else:
            zone.current_occupancy = max(0, zone.current_occupancy - 1)

    ip = _inet_or_none(client_ip(request))
    result = AccessResult.Granted if decision.allowed else AccessResult.Denied
    event = AccessEvent(
        subject_type=subject_type,
        subject_id=subject_id,
        zone_id=zone.id,
        result=result,
        reason=decision.reason,
        ip=ip,
    )
    db.add(event)
    db.flush()
    audit_chain.append(
        db,
        actor.id,
        f"access.{result.value.lower()}",
        f"zones/{zone.id}",
        {
            "event_id": event.id,
            "subject_type": subject_type,
            "subject_id": subject_id,
            "direction": payload.direction,
            "reason": decision.reason,
            "grant_id": grant.id if grant is not None else None,
            "ip": ip,
        },
    )
    db.commit()
    return AccessAttemptResponse(
        event_id=event.id,
        zone_id=zone.id,
        subject_type=subject_type,
        subject_id=subject_id,
        direction=payload.direction,
        result=result,
        reason=decision.reason,
        current_occupancy=zone.current_occupancy,
    )

"""Zero-trust zone access policy evaluation.

A pure policy decision point: no database, no FastAPI, no clock of its own. Callers load the
subject, zone and candidate grant and pass ``now`` explicitly, so every decision is
reproducible in a unit test.

Deny by default. Checks run in a fixed order and the first failure is returned as a
machine-readable reason, which is what gets written to the access event and the audit log:

1. the subject is active (users: ``is_active``; visitors: ``Approved`` and inside the window)
2. the subject's clearance satisfies the zone's ``min_clearance``
3. a grant for exactly this subject and zone exists and is neither revoked nor expired
4. on entry, the zone is below capacity
"""

import enum
from dataclasses import dataclass
from datetime import datetime

from app.models.enums import VisitorStatus
from app.models.grant import ZoneAccessGrant
from app.models.user import User
from app.models.visitor import Visitor
from app.models.zone import Zone

Subject = User | Visitor


class Direction(enum.StrEnum):
    Entry = "Entry"
    Exit = "Exit"


class Reason(enum.StrEnum):
    ACCESS_GRANTED = "ACCESS_GRANTED"
    UNKNOWN_SUBJECT = "UNKNOWN_SUBJECT"
    UNKNOWN_ZONE = "UNKNOWN_ZONE"
    SUBJECT_INACTIVE = "SUBJECT_INACTIVE"
    VISITOR_NOT_APPROVED = "VISITOR_NOT_APPROVED"
    OUTSIDE_VISIT_WINDOW = "OUTSIDE_VISIT_WINDOW"
    INSUFFICIENT_CLEARANCE = "INSUFFICIENT_CLEARANCE"
    NO_GRANT = "NO_GRANT"
    GRANT_MISMATCH = "GRANT_MISMATCH"
    GRANT_REVOKED = "GRANT_REVOKED"
    GRANT_EXPIRED = "GRANT_EXPIRED"
    ZONE_AT_CAPACITY = "ZONE_AT_CAPACITY"


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    reason: str

    @classmethod
    def deny(cls, reason: Reason) -> "Decision":
        return cls(allowed=False, reason=reason.value)


GRANTED = Decision(allowed=True, reason=Reason.ACCESS_GRANTED.value)


def subject_activity(subject: Subject, now: datetime) -> Reason | None:
    """The reason ``subject`` is not currently active, or None if it is."""
    if isinstance(subject, User):
        return None if subject.is_active is True else Reason.SUBJECT_INACTIVE
    if subject.status != VisitorStatus.Approved:
        return Reason.VISITOR_NOT_APPROVED
    if not subject.visit_start <= now < subject.visit_end:
        return Reason.OUTSIDE_VISIT_WINDOW
    return None


def grant_matches(grant: ZoneAccessGrant, subject: Subject, zone: Zone) -> bool:
    """True if ``grant`` was issued to exactly ``subject`` for exactly ``zone``."""
    if grant.zone_id != zone.id:
        return False
    if isinstance(subject, User):
        return grant.user_id == subject.id and grant.visitor_id is None
    return grant.visitor_id == subject.id and grant.user_id is None


def _grant_problem(
    grant: ZoneAccessGrant | None, subject: Subject, zone: Zone, now: datetime
) -> Reason | None:
    if grant is None:
        return Reason.NO_GRANT
    if not grant_matches(grant, subject, zone):
        return Reason.GRANT_MISMATCH
    if grant.revoked_at is not None and grant.revoked_at <= now:
        return Reason.GRANT_REVOKED
    if now >= grant.expires_at:
        return Reason.GRANT_EXPIRED
    return None


def evaluate_zone_access(
    subject: Subject | None,
    zone: Zone | None,
    grant: ZoneAccessGrant | None,
    now: datetime,
    direction: Direction = Direction.Entry,
) -> Decision:
    """Decide whether ``subject`` may pass into (or out of) ``zone`` at ``now``.

    ``now`` must be timezone-aware; a naive timestamp is a programming error, not a denial.
    A missing subject or zone is denied rather than raised, so a caller can never turn a
    lookup miss into an implicit allow.
    """
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if subject is None:
        return Decision.deny(Reason.UNKNOWN_SUBJECT)
    if zone is None:
        return Decision.deny(Reason.UNKNOWN_ZONE)

    inactive = subject_activity(subject, now)
    if inactive is not None:
        return Decision.deny(inactive)
    if not subject.clearance.satisfies(zone.min_clearance):
        return Decision.deny(Reason.INSUFFICIENT_CLEARANCE)
    grant_problem = _grant_problem(grant, subject, zone, now)
    if grant_problem is not None:
        return Decision.deny(grant_problem)
    if direction == Direction.Entry and zone.current_occupancy >= zone.capacity:
        return Decision.deny(Reason.ZONE_AT_CAPACITY)
    return GRANTED

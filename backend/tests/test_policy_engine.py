"""Unit tests: the pure zone-access policy engine (no database, no HTTP).

The core matrix crosses 3 roles x 3 subject clearances x 3 zone levels x active/inactive x
5 grant states (270 cases) and checks every decision against an independently written
oracle. Role is deliberately part of the matrix: zero trust means an Admin gets no bypass.
"""

import enum
import itertools
import uuid
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest

from app.models.enums import Clearance, Role, VisitorStatus, VisitorType
from app.models.grant import ZoneAccessGrant
from app.models.user import User
from app.models.visitor import Visitor
from app.models.zone import Zone
from app.services.policy_engine import (
    GRANTED,
    Decision,
    Direction,
    Reason,
    evaluate_zone_access,
    grant_matches,
    subject_activity,
)

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)


class GrantState(enum.Enum):
    NONE = "none"
    VALID = "valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    OTHER_ZONE = "other_zone"


def _user(
    role: Role = Role.Personnel,
    clearance: Clearance = Clearance.Reliability,
    *,
    active: bool = True,
) -> User:
    return User(
        id=uuid.uuid4(),
        email="subject@example.com",
        full_name="Subject",
        password_hash="unused",
        role=role,
        clearance=clearance,
        is_active=active,
    )


def _visitor(
    status: VisitorStatus = VisitorStatus.Approved,
    clearance: Clearance = Clearance.Reliability,
    *,
    start: datetime = NOW - timedelta(hours=1),
    end: datetime = NOW + timedelta(hours=1),
) -> Visitor:
    return Visitor(
        id=uuid.uuid4(),
        full_name="Guest",
        visitor_type=VisitorType.Visitor,
        host_user_id=uuid.uuid4(),
        clearance=clearance,
        status=status,
        visit_start=start,
        visit_end=end,
    )


def _zone(
    min_clearance: Clearance = Clearance.Reliability, *, capacity: int = 10, occ: int = 0
) -> Zone:
    return Zone(
        id=uuid.uuid4(),
        name="Zone",
        description="",
        min_clearance=min_clearance,
        capacity=capacity,
        current_occupancy=occ,
    )


def _grant(
    subject: User | Visitor,
    zone: Zone,
    *,
    expires_at: datetime = NOW + timedelta(days=1),
    revoked_at: datetime | None = None,
    zone_id: uuid.UUID | None = None,
) -> ZoneAccessGrant:
    is_user = isinstance(subject, User)
    return ZoneAccessGrant(
        id=uuid.uuid4(),
        zone_id=zone_id or zone.id,
        user_id=subject.id if is_user else None,
        visitor_id=None if is_user else subject.id,
        granted_by=uuid.uuid4(),
        expires_at=expires_at,
        revoked_at=revoked_at,
        created_at=NOW - timedelta(days=1),
    )


def _grant_for(state: GrantState, subject: User, zone: Zone) -> ZoneAccessGrant | None:
    match state:
        case GrantState.NONE:
            return None
        case GrantState.VALID:
            return _grant(subject, zone)
        case GrantState.EXPIRED:
            return _grant(subject, zone, expires_at=NOW - timedelta(seconds=1))
        case GrantState.REVOKED:
            return _grant(subject, zone, revoked_at=NOW - timedelta(minutes=5))
        case GrantState.OTHER_ZONE:
            return _grant(subject, zone, zone_id=uuid.uuid4())


_GRANT_REASONS = {
    GrantState.NONE: Reason.NO_GRANT,
    GrantState.EXPIRED: Reason.GRANT_EXPIRED,
    GrantState.REVOKED: Reason.GRANT_REVOKED,
    GrantState.OTHER_ZONE: Reason.GRANT_MISMATCH,
}


def _oracle(clearance: Clearance, zone_level: Clearance, active: bool, state: GrantState) -> str:
    """Expected outcome, written from the spec independently of the engine's code."""
    if not active:
        return Reason.SUBJECT_INACTIVE
    if int(clearance) < int(zone_level):
        return Reason.INSUFFICIENT_CLEARANCE
    if state is not GrantState.VALID:
        return _GRANT_REASONS[state]
    return Reason.ACCESS_GRANTED


MATRIX = list(itertools.product(Role, Clearance, Clearance, [True, False], GrantState))


def test_matrix_size() -> None:
    assert len(MATRIX) == 3 * 3 * 3 * 2 * 5


@pytest.mark.parametrize(
    ("role", "clearance", "zone_level", "active", "grant_state"),
    MATRIX,
    ids=[
        f"{r}-{c.name}-zone_{z.name}-{'active' if a else 'inactive'}-{g.value}"
        for r, c, z, a, g in MATRIX
    ],
)
def test_access_matrix(
    role: Role, clearance: Clearance, zone_level: Clearance, active: bool, grant_state: GrantState
) -> None:
    subject = _user(role, clearance, active=active)
    zone = _zone(zone_level)
    grant = _grant_for(grant_state, subject, zone)

    decision = evaluate_zone_access(subject, zone, grant, NOW)

    expected = _oracle(clearance, zone_level, active, grant_state)
    assert decision.reason == expected
    assert decision.allowed is (expected == Reason.ACCESS_GRANTED)


def test_only_the_all_conditions_true_cells_are_allowed() -> None:
    allowed = [
        cell
        for cell in MATRIX
        if evaluate_zone_access(
            subject := _user(cell[0], cell[1], active=cell[3]),
            zone := _zone(cell[2]),
            _grant_for(cell[4], subject, zone),
            NOW,
        ).allowed
    ]
    # Per role: 6 (clearance, zone) pairs where clearance >= zone, active, valid grant.
    assert len(allowed) == 3 * 6
    assert all(c >= z and a and g is GrantState.VALID for _, c, z, a, g in allowed)


# --- Capacity -----------------------------------------------------------------------------


def test_entry_denied_at_capacity() -> None:
    subject = _user()
    zone = _zone(capacity=2, occ=2)
    decision = evaluate_zone_access(subject, zone, _grant(subject, zone), NOW)
    assert decision == Decision(allowed=False, reason="ZONE_AT_CAPACITY")


def test_entry_allowed_one_below_capacity() -> None:
    subject = _user()
    zone = _zone(capacity=2, occ=1)
    assert evaluate_zone_access(subject, zone, _grant(subject, zone), NOW) == GRANTED


def test_exit_ignores_capacity_but_not_the_other_checks() -> None:
    subject = _user()
    zone = _zone(capacity=2, occ=2)
    grant = _grant(subject, zone)
    assert evaluate_zone_access(subject, zone, grant, NOW, Direction.Exit) == GRANTED
    revoked = _grant(subject, zone, revoked_at=NOW)
    assert (
        evaluate_zone_access(subject, zone, revoked, NOW, Direction.Exit).reason == "GRANT_REVOKED"
    )


def test_capacity_is_checked_last() -> None:
    subject = _user(clearance=Clearance.Reliability)
    zone = _zone(Clearance.Top_Secret, capacity=1, occ=1)
    assert evaluate_zone_access(subject, zone, None, NOW).reason == "INSUFFICIENT_CLEARANCE"


# --- Grant edge cases ---------------------------------------------------------------------


def test_grant_expiry_boundary_is_exclusive() -> None:
    subject = _user()
    zone = _zone()
    at_expiry = _grant(subject, zone, expires_at=NOW)
    assert evaluate_zone_access(subject, zone, at_expiry, NOW).reason == "GRANT_EXPIRED"
    just_before = _grant(subject, zone, expires_at=NOW + timedelta(microseconds=1))
    assert evaluate_zone_access(subject, zone, just_before, NOW) == GRANTED


def test_future_revocation_is_not_yet_effective() -> None:
    subject = _user()
    zone = _zone()
    grant = _grant(subject, zone, revoked_at=NOW + timedelta(minutes=1))
    assert evaluate_zone_access(subject, zone, grant, NOW) == GRANTED


def test_revocation_takes_precedence_over_expiry() -> None:
    subject = _user()
    zone = _zone()
    grant = _grant(
        subject, zone, expires_at=NOW - timedelta(days=1), revoked_at=NOW - timedelta(days=2)
    )
    assert evaluate_zone_access(subject, zone, grant, NOW).reason == "GRANT_REVOKED"


def test_grant_for_another_user_is_a_mismatch() -> None:
    subject = _user()
    zone = _zone()
    someone_else = _grant(_user(), zone)
    assert evaluate_zone_access(subject, zone, someone_else, NOW).reason == "GRANT_MISMATCH"


def test_user_grant_cannot_be_used_by_visitor_with_same_id() -> None:
    user = _user()
    visitor = _visitor()
    visitor.id = user.id
    zone = _zone()
    assert not grant_matches(_grant(user, zone), visitor, zone)
    assert evaluate_zone_access(visitor, zone, _grant(user, zone), NOW).reason == "GRANT_MISMATCH"


# --- Visitors -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (VisitorStatus.Approved, "ACCESS_GRANTED"),
        (VisitorStatus.Pending, "VISITOR_NOT_APPROVED"),
        (VisitorStatus.Denied, "VISITOR_NOT_APPROVED"),
        (VisitorStatus.Expired, "VISITOR_NOT_APPROVED"),
    ],
)
def test_visitor_status(status: VisitorStatus, expected: str) -> None:
    visitor = _visitor(status)
    zone = _zone()
    assert evaluate_zone_access(visitor, zone, _grant(visitor, zone), NOW).reason == expected


@pytest.mark.parametrize(
    ("start", "end", "expected"),
    [
        (NOW, NOW + timedelta(hours=1), "ACCESS_GRANTED"),  # start is inclusive
        (NOW - timedelta(hours=1), NOW, "OUTSIDE_VISIT_WINDOW"),  # end is exclusive
        (NOW + timedelta(minutes=1), NOW + timedelta(hours=1), "OUTSIDE_VISIT_WINDOW"),
        (NOW - timedelta(hours=2), NOW - timedelta(hours=1), "OUTSIDE_VISIT_WINDOW"),
    ],
)
def test_visitor_window(start: datetime, end: datetime, expected: str) -> None:
    visitor = _visitor(start=start, end=end)
    zone = _zone()
    assert evaluate_zone_access(visitor, zone, _grant(visitor, zone), NOW).reason == expected


@pytest.mark.parametrize(
    ("clearance", "zone_level", "allowed"),
    [(c, z, c >= z) for c, z in itertools.product(Clearance, Clearance)],
)
def test_visitor_clearance(clearance: Clearance, zone_level: Clearance, allowed: bool) -> None:
    visitor = _visitor(clearance=clearance)
    zone = _zone(zone_level)
    decision = evaluate_zone_access(visitor, zone, _grant(visitor, zone), NOW)
    assert decision.allowed is allowed
    assert decision.reason == ("ACCESS_GRANTED" if allowed else "INSUFFICIENT_CLEARANCE")


def test_subject_activity_helper() -> None:
    assert subject_activity(_user(), NOW) is None
    assert subject_activity(_user(active=False), NOW) is Reason.SUBJECT_INACTIVE
    assert subject_activity(_visitor(VisitorStatus.Pending), NOW) is Reason.VISITOR_NOT_APPROVED


# --- Fail-closed inputs -------------------------------------------------------------------


def test_missing_subject_or_zone_is_denied() -> None:
    zone = _zone()
    assert evaluate_zone_access(None, zone, None, NOW) == Decision(False, "UNKNOWN_SUBJECT")
    assert evaluate_zone_access(_user(), None, None, NOW) == Decision(False, "UNKNOWN_ZONE")


def test_naive_now_is_rejected() -> None:
    subject = _user()
    zone = _zone()
    with pytest.raises(ValueError, match="timezone-aware"):
        evaluate_zone_access(subject, zone, _grant(subject, zone), datetime(2026, 11, 9, 12, 0))


def test_unset_is_active_is_not_treated_as_active() -> None:
    subject = _user()
    subject.is_active = None  # type: ignore[assignment]
    zone = _zone()
    assert (
        evaluate_zone_access(subject, zone, _grant(subject, zone), NOW).reason == "SUBJECT_INACTIVE"
    )


def test_decision_is_immutable() -> None:
    with pytest.raises(FrozenInstanceError):
        GRANTED.allowed = False  # type: ignore[misc]


def test_reasons_are_plain_strings_for_auditing() -> None:
    decision = evaluate_zone_access(_user(), _zone(), None, NOW)
    assert type(decision.reason) is str
    assert decision.reason == "NO_GRANT"

"""Integration tests: users, zones, grants and access attempts over HTTP.

Focus: privilege escalation (Personnel/SecurityOfficer reaching Admin powers, Admins changing
their own privileges), IDOR (Personnel reading other users), grant provisioning rules, the
access-attempt flow, and the audit entries every mutation and decision leaves behind.

Real PostgreSQL as the restricted ``aegis_app`` role plus fakeredis; see tests/pg.py.
"""

import itertools
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from redis import Redis
from sqlalchemy import Engine, create_engine, make_url, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_migration_settings, get_settings
from app.core.redis import get_redis
from app.db.session import get_db
from app.main import create_app
from app.models.audit import GENESIS_HASH
from tests.pg import integration, migrate, require_test_db_url, reset_data

pytestmark = integration

PASSWORD = "correct-horse-battery-staple"
V1 = "/api/v1"
CLIENT_IP = "203.0.113.7"


@pytest.fixture(scope="module")
def owner_engine() -> Iterator[Engine]:
    eng = create_engine(require_test_db_url())
    migrate(eng, "downgrade")
    migrate(eng, "upgrade")
    try:
        yield eng
    finally:
        migrate(eng, "downgrade")
        eng.dispose()


@pytest.fixture(scope="module")
def app_engine(owner_engine: Engine) -> Iterator[Engine]:
    url = make_url(require_test_db_url()).set(
        username="aegis_app",
        password=get_migration_settings().app_db_password.get_secret_value(),
    )
    eng = create_engine(url)
    try:
        yield eng
    finally:
        eng.dispose()


@pytest.fixture
def api(
    owner_engine: Engine, app_engine: Engine, fake_redis: Redis, monkeypatch: pytest.MonkeyPatch
) -> Iterator[TestClient]:
    reset_data(owner_engine)
    monkeypatch.setattr(get_settings(), "rate_limit_login_requests", 1000)
    monkeypatch.setattr(get_settings(), "rate_limit_default_requests", 10_000)
    factory = sessionmaker(bind=app_engine, autoflush=False, expire_on_commit=False)

    def _db() -> Iterator[Session]:
        with factory() as session:
            yield session

    app = create_app()
    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_redis] = lambda: fake_redis
    with TestClient(app, base_url="https://testserver", client=(CLIENT_IP, 50000)) as client:
        yield client


@dataclass
class Actor:
    id: str
    token: str

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}


@dataclass
class Cast:
    admin: Actor
    officer: Actor
    alice: Actor  # Personnel, Reliability
    bob: Actor  # Personnel, Reliability


def _login(api: TestClient, email: str) -> str:
    response = api.post(f"{V1}/auth/login", json={"email": email, "password": PASSWORD})
    api.cookies.clear()
    assert response.status_code == 200, response.text
    token: str = response.json()["access_token"]
    return token


def _create(api: TestClient, admin: Actor | None, email: str, **extra: str) -> Actor:
    body = {"email": email, "full_name": email.split("@")[0], "password": PASSWORD, **extra}
    response = api.post(f"{V1}/auth/register", json=body, headers=admin.headers if admin else {})
    assert response.status_code == 201, response.text
    return Actor(id=response.json()["id"], token=_login(api, email))


@pytest.fixture
def cast(api: TestClient) -> Cast:
    admin = _create(api, None, "admin@example.com", clearance="Top_Secret")
    return Cast(
        admin=admin,
        officer=_create(
            api, admin, "officer@example.com", role="SecurityOfficer", clearance="Secret_Level_II"
        ),
        alice=_create(api, admin, "alice@example.com"),
        bob=_create(api, admin, "bob@example.com"),
    )


def _user_row(owner_engine: Engine, user_id: str) -> dict[str, Any]:
    with owner_engine.connect() as conn:
        row = conn.execute(
            text("SELECT role::text, clearance::text, is_active FROM users WHERE id = :id"),
            {"id": user_id},
        ).one()
    return {"role": row[0], "clearance": row[1], "is_active": row[2]}


def _audit(owner_engine: Engine) -> list[dict[str, Any]]:
    with owner_engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT prev_hash, entry_hash, actor_id::text, action, resource, payload "
                "FROM audit_logs ORDER BY id"
            )
        ).all()
    return [
        {
            "prev_hash": r[0],
            "entry_hash": r[1],
            "actor_id": r[2],
            "action": r[3],
            "resource": r[4],
            "payload": r[5],
        }
        for r in rows
    ]


def _actions(owner_engine: Engine) -> list[str]:
    return [entry["action"] for entry in _audit(owner_engine)]


def _patch_user(api: TestClient, actor: Actor, user_id: str, **body: Any) -> httpx.Response:
    response: httpx.Response = api.patch(f"{V1}/users/{user_id}", json=body, headers=actor.headers)
    return response


def _zone(api: TestClient, admin: Actor, name: str, level: str, capacity: int = 10) -> str:
    response = api.post(
        f"{V1}/zones",
        json={"name": name, "min_clearance": level, "capacity": capacity},
        headers=admin.headers,
    )
    assert response.status_code == 201, response.text
    zone_id: str = response.json()["id"]
    return zone_id


def _future(days: int = 1) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).isoformat()


def _grant(
    api: TestClient, actor: Actor, zone_id: str, user_id: str, **extra: Any
) -> httpx.Response:
    body = {"user_id": user_id, "expires_at": _future(), **extra}
    response: httpx.Response = api.post(
        f"{V1}/zones/{zone_id}/grant", json=body, headers=actor.headers
    )
    return response


def _attempt(api: TestClient, actor: Actor, zone_id: str, **body: Any) -> httpx.Response:
    response: httpx.Response = api.post(
        f"{V1}/zones/{zone_id}/access-attempt", json=body, headers=actor.headers
    )
    return response


# --- IDOR ---------------------------------------------------------------------------------


def test_personnel_can_read_only_themselves(api: TestClient, cast: Cast) -> None:
    own = api.get(f"{V1}/users/{cast.alice.id}", headers=cast.alice.headers)
    assert own.status_code == 200
    assert own.json()["email"] == "alice@example.com"

    other = api.get(f"{V1}/users/{cast.bob.id}", headers=cast.alice.headers)
    admin = api.get(f"{V1}/users/{cast.admin.id}", headers=cast.alice.headers)
    missing = api.get(f"{V1}/users/{uuid.uuid4()}", headers=cast.alice.headers)
    # Existing and non-existent ids are indistinguishable, so ids cannot be enumerated.
    for response in (other, admin, missing):
        assert response.status_code == 404
        assert response.json() == {"detail": "User not found"}
        assert "bob@example.com" not in response.text


def test_personnel_cannot_list_users(api: TestClient, cast: Cast) -> None:
    assert api.get(f"{V1}/users", headers=cast.alice.headers).status_code == 403


def test_unauthenticated_cannot_read_users(api: TestClient, cast: Cast) -> None:
    assert api.get(f"{V1}/users").status_code == 401
    assert api.get(f"{V1}/users/{cast.alice.id}").status_code == 401


def test_officer_and_admin_read_everyone(api: TestClient, cast: Cast) -> None:
    for actor in (cast.officer, cast.admin):
        listing = api.get(f"{V1}/users", headers=actor.headers)
        assert listing.status_code == 200
        assert len(listing.json()) == 4
        assert "password_hash" not in listing.text
        assert api.get(f"{V1}/users/{cast.bob.id}", headers=actor.headers).status_code == 200
    assert api.get(f"{V1}/users/{uuid.uuid4()}", headers=cast.admin.headers).status_code == 404


def test_malformed_user_id_is_rejected(api: TestClient, cast: Cast) -> None:
    assert api.get(f"{V1}/users/not-a-uuid", headers=cast.admin.headers).status_code == 422


# --- Privilege escalation -----------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        {"role": "Admin"},
        {"role": "SecurityOfficer"},
        {"clearance": "Top_Secret"},
        {"is_active": True},
        {"full_name": "Renamed"},
    ],
)
def test_personnel_cannot_modify_themselves(
    api: TestClient, cast: Cast, owner_engine: Engine, body: dict[str, Any]
) -> None:
    before = _user_row(owner_engine, cast.alice.id)
    response = _patch_user(api, cast.alice, cast.alice.id, **body)
    assert response.status_code == 403
    assert _user_row(owner_engine, cast.alice.id) == before


@pytest.mark.parametrize(
    "body",
    [{"role": "Admin"}, {"clearance": "Top_Secret"}, {"is_active": False}, {"role": "Personnel"}],
)
def test_security_officer_is_read_only(
    api: TestClient, cast: Cast, owner_engine: Engine, body: dict[str, Any]
) -> None:
    for target in (cast.officer.id, cast.alice.id):
        before = _user_row(owner_engine, target)
        assert _patch_user(api, cast.officer, target, **body).status_code == 403
        assert _user_row(owner_engine, target) == before


def test_non_admins_cannot_register_admins(api: TestClient, cast: Cast) -> None:
    body = {
        "email": "mallory@example.com",
        "full_name": "Mallory",
        "password": PASSWORD,
        "role": "Admin",
        "clearance": "Top_Secret",
    }
    for actor in (cast.alice, cast.officer):
        response = api.post(f"{V1}/auth/register", json=body, headers=actor.headers)
        assert response.status_code == 403


def test_mass_assignment_is_rejected(api: TestClient, cast: Cast) -> None:
    response = _patch_user(api, cast.admin, cast.alice.id, password_hash="x", mfa_enabled=False)
    assert response.status_code == 422


@pytest.mark.parametrize(
    "body",
    [
        {"role": "Personnel"},
        {"role": "SecurityOfficer"},
        {"is_active": False},
        {"clearance": "Reliability"},
    ],
)
def test_admin_cannot_demote_or_deactivate_self(
    api: TestClient, cast: Cast, owner_engine: Engine, body: dict[str, Any]
) -> None:
    response = _patch_user(api, cast.admin, cast.admin.id, **body)
    assert response.status_code == 403
    assert response.json() == {
        "detail": "Admins cannot change their own role, clearance or activation"
    }
    assert _user_row(owner_engine, cast.admin.id) == {
        "role": "Admin",
        "clearance": "Top_Secret",
        "is_active": True,
    }


def test_admin_may_rename_self_and_noop_privilege_fields(api: TestClient, cast: Cast) -> None:
    response = _patch_user(
        api, cast.admin, cast.admin.id, full_name="Root", role="Admin", is_active=True
    )
    assert response.status_code == 200
    assert response.json()["full_name"] == "Root"


def test_admin_grants_admin_role_and_top_secret(
    api: TestClient, cast: Cast, owner_engine: Engine
) -> None:
    response = _patch_user(api, cast.admin, cast.bob.id, role="Admin", clearance="Top_Secret")
    assert response.status_code == 200
    assert response.json()["role"] == "Admin"
    assert response.json()["clearance"] == "Top_Secret"
    # The promotion is effective immediately because authorization reads the DB row.
    assert api.get(f"{V1}/users", headers=cast.bob.headers).status_code == 200

    entry = _audit(owner_engine)[-1]
    assert entry["action"] == "user.update"
    assert entry["actor_id"] == cast.admin.id
    assert entry["resource"] == f"users/{cast.bob.id}"
    assert entry["payload"] == {
        "changes": {
            "role": {"from": "Personnel", "to": "Admin"},
            "clearance": {"from": "Reliability", "to": "Top_Secret"},
        }
    }


def test_demotion_takes_effect_on_next_request(api: TestClient, cast: Cast) -> None:
    assert _patch_user(api, cast.admin, cast.officer.id, role="Personnel").status_code == 200
    assert api.get(f"{V1}/users", headers=cast.officer.headers).status_code == 403


def test_deactivation_kills_sessions(api: TestClient, cast: Cast) -> None:
    login = api.post(f"{V1}/auth/login", json={"email": "bob@example.com", "password": PASSWORD})
    refresh = login.cookies["aegis_refresh"]
    api.cookies.clear()

    assert _patch_user(api, cast.admin, cast.bob.id, is_active=False).status_code == 200
    assert api.get(f"{V1}/auth/me", headers=cast.bob.headers).status_code == 401
    again = api.post(f"{V1}/auth/refresh", headers={"Cookie": f"aegis_refresh={refresh}"})
    assert again.status_code == 401


def test_admin_can_demote_another_admin(api: TestClient, cast: Cast) -> None:
    assert _patch_user(api, cast.admin, cast.bob.id, role="Admin").status_code == 200
    # The second Admin may demote the first; only *self*-demotion is forbidden.
    assert _patch_user(api, cast.bob, cast.admin.id, role="Personnel").status_code == 200
    assert _patch_user(api, cast.bob, cast.bob.id, role="Personnel").status_code == 403


def test_update_unknown_user_is_404(api: TestClient, cast: Cast) -> None:
    assert _patch_user(api, cast.admin, str(uuid.uuid4()), role="Admin").status_code == 404


def test_registration_is_audited(api: TestClient, cast: Cast, owner_engine: Engine) -> None:
    # Each _create also logs the new user in, which writes its own auth.login entry.
    log = [e for e in _audit(owner_engine) if e["action"].startswith("user.")]
    assert [e["action"] for e in log] == ["user.bootstrap"] + ["user.create"] * 3
    assert log[0]["actor_id"] is None
    assert all(e["actor_id"] == cast.admin.id for e in log[1:])
    assert log[1]["payload"] == {
        "email": "officer@example.com",
        "role": "SecurityOfficer",
        "clearance": "Secret_Level_II",
    }


# --- Zone CRUD ----------------------------------------------------------------------------


def test_zone_crud_is_admin_only(api: TestClient, cast: Cast, owner_engine: Engine) -> None:
    body = {"name": "Vault", "min_clearance": "Top_Secret", "capacity": 2}
    for actor in (cast.alice, cast.officer):
        assert api.post(f"{V1}/zones", json=body, headers=actor.headers).status_code == 403

    zone_id = _zone(api, cast.admin, "Vault", "Top_Secret", 2)
    for actor in (cast.alice, cast.officer):
        patch = api.patch(f"{V1}/zones/{zone_id}", json={"capacity": 9}, headers=actor.headers)
        assert patch.status_code == 403
        assert api.delete(f"{V1}/zones/{zone_id}", headers=actor.headers).status_code == 403

    updated = api.patch(
        f"{V1}/zones/{zone_id}",
        json={"description": "Server vault", "capacity": 3},
        headers=cast.admin.headers,
    )
    assert updated.status_code == 200
    assert updated.json()["capacity"] == 3
    assert api.delete(f"{V1}/zones/{zone_id}", headers=cast.admin.headers).status_code == 204
    assert api.get(f"{V1}/zones/{zone_id}", headers=cast.admin.headers).status_code == 404

    assert _actions(owner_engine)[-3:] == ["zone.create", "zone.update", "zone.delete"]
    assert _audit(owner_engine)[-2]["payload"] == {
        "changes": {
            "description": {"from": "", "to": "Server vault"},
            "capacity": {"from": 2, "to": 3},
        }
    }


def test_any_authenticated_user_can_list_zones(api: TestClient, cast: Cast) -> None:
    _zone(api, cast.admin, "Lobby", "Reliability")
    _zone(api, cast.admin, "Ops", "Secret_Level_II")
    listing = api.get(f"{V1}/zones", headers=cast.alice.headers)
    assert listing.status_code == 200
    assert [z["name"] for z in listing.json()] == ["Lobby", "Ops"]
    assert listing.json()[1]["min_clearance"] == "Secret_Level_II"
    assert api.get(f"{V1}/zones").status_code == 401


def test_zone_validation_and_conflicts(api: TestClient, cast: Cast) -> None:
    h = cast.admin.headers
    _zone(api, cast.admin, "Lobby", "Reliability")
    dup = api.post(
        f"{V1}/zones",
        json={"name": "Lobby", "min_clearance": "Reliability", "capacity": 1},
        headers=h,
    )
    assert dup.status_code == 409
    bad = [
        {"name": "X", "min_clearance": "Cosmic", "capacity": 1},
        {"name": "X", "min_clearance": "Reliability", "capacity": 0},
        {"name": "", "min_clearance": "Reliability", "capacity": 1},
        {"name": "X", "min_clearance": 3, "capacity": 1},
    ]
    for body in bad:
        assert api.post(f"{V1}/zones", json=body, headers=h).status_code == 422


def test_capacity_cannot_drop_below_occupancy(api: TestClient, cast: Cast) -> None:
    zone_id = _zone(api, cast.admin, "Lab", "Reliability", 5)
    assert _grant(api, cast.admin, zone_id, cast.alice.id).status_code == 201
    assert _grant(api, cast.admin, zone_id, cast.bob.id).status_code == 201
    assert _attempt(api, cast.alice, zone_id).json()["result"] == "Granted"
    assert _attempt(api, cast.bob, zone_id).json()["result"] == "Granted"
    shrink = api.patch(f"{V1}/zones/{zone_id}", json={"capacity": 1}, headers=cast.admin.headers)
    assert shrink.status_code == 409


# --- Grants -------------------------------------------------------------------------------


def test_grant_refused_below_zone_clearance(
    api: TestClient, cast: Cast, owner_engine: Engine
) -> None:
    vault = _zone(api, cast.admin, "Vault", "Top_Secret")
    for actor in (cast.admin, cast.officer):
        response = _grant(api, actor, vault, cast.alice.id)
        assert response.status_code == 422
        detail = response.json()["detail"]
        assert detail["reason"] == "INSUFFICIENT_CLEARANCE"
        assert "Reliability" in detail["message"]

    with owner_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM zone_access_grants")).scalar_one() == 0
    refused = _audit(owner_engine)[-1]
    assert refused["action"] == "zone.grant.refused"
    assert refused["actor_id"] == cast.officer.id
    assert refused["payload"]["reason"] == "INSUFFICIENT_CLEARANCE"
    assert refused["payload"]["subject_id"] == cast.alice.id


def test_personnel_cannot_provision_grants(api: TestClient, cast: Cast) -> None:
    lobby = _zone(api, cast.admin, "Lobby", "Reliability")
    assert _grant(api, cast.alice, lobby, cast.alice.id).status_code == 403
    assert api.get(f"{V1}/zones/{lobby}/grants", headers=cast.alice.headers).status_code == 403


def test_officer_provisions_and_revokes_grant(
    api: TestClient, cast: Cast, owner_engine: Engine
) -> None:
    lobby = _zone(api, cast.admin, "Lobby", "Reliability")
    created = _grant(api, cast.officer, lobby, cast.alice.id)
    assert created.status_code == 201
    grant = created.json()
    assert grant["user_id"] == cast.alice.id
    assert grant["granted_by"] == cast.officer.id
    assert grant["revoked_at"] is None

    listing = api.get(f"{V1}/zones/{lobby}/grants", headers=cast.officer.headers)
    assert [g["id"] for g in listing.json()] == [grant["id"]]

    revoked = api.post(
        f"{V1}/zones/{lobby}/grants/{grant['id']}/revoke", headers=cast.officer.headers
    )
    assert revoked.status_code == 200
    assert revoked.json()["revoked_at"] is not None
    assert _actions(owner_engine)[-2:] == ["zone.grant.create", "zone.grant.revoke"]

    other_zone = _zone(api, cast.admin, "Other", "Reliability")
    wrong = api.post(
        f"{V1}/zones/{other_zone}/grants/{grant['id']}/revoke", headers=cast.admin.headers
    )
    assert wrong.status_code == 404


def test_grant_input_validation(api: TestClient, cast: Cast) -> None:
    lobby = _zone(api, cast.admin, "Lobby", "Reliability")
    past = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    assert _grant(api, cast.admin, lobby, cast.alice.id, expires_at=past).status_code == 422
    naive = datetime.now().replace(tzinfo=None).isoformat()
    assert _grant(api, cast.admin, lobby, cast.alice.id, expires_at=naive).status_code == 422
    both = _grant(api, cast.admin, lobby, cast.alice.id, visitor_id=str(uuid.uuid4()))
    assert both.status_code == 422
    neither = api.post(
        f"{V1}/zones/{lobby}/grant", json={"expires_at": _future()}, headers=cast.admin.headers
    )
    assert neither.status_code == 422
    assert _grant(api, cast.admin, lobby, str(uuid.uuid4())).status_code == 404
    assert _grant(api, cast.admin, str(uuid.uuid4()), cast.alice.id).status_code == 404


# --- Access attempts ----------------------------------------------------------------------


def _events(owner_engine: Engine) -> list[tuple[str, str, str, str | None]]:
    with owner_engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT subject_id::text, result::text, reason, host(ip) "
                "FROM access_events ORDER BY created_at, id"
            )
        ).all()
    return [(r[0], r[1], r[2], r[3]) for r in rows]


def test_access_attempt_records_denied_and_granted(
    api: TestClient, cast: Cast, owner_engine: Engine
) -> None:
    lobby = _zone(api, cast.admin, "Lobby", "Reliability", capacity=1)

    denied = _attempt(api, cast.alice, lobby)
    assert denied.status_code == 200
    assert denied.json()["result"] == "Denied"
    assert denied.json()["reason"] == "NO_GRANT"
    assert denied.json()["current_occupancy"] == 0

    assert _grant(api, cast.officer, lobby, cast.alice.id).status_code == 201
    granted = _attempt(api, cast.alice, lobby)
    assert granted.json()["result"] == "Granted"
    assert granted.json()["reason"] == "ACCESS_GRANTED"
    assert granted.json()["current_occupancy"] == 1

    assert _events(owner_engine) == [
        (cast.alice.id, "Denied", "NO_GRANT", CLIENT_IP),
        (cast.alice.id, "Granted", "ACCESS_GRANTED", CLIENT_IP),
    ]
    decisions = [e for e in _audit(owner_engine) if e["action"].startswith("access.")]
    assert [e["action"] for e in decisions] == ["access.denied", "access.granted"]
    assert decisions[1]["payload"]["event_id"] == granted.json()["event_id"]
    assert decisions[1]["payload"]["ip"] == CLIENT_IP
    assert decisions[1]["payload"]["direction"] == "Entry"


def test_capacity_and_exit(api: TestClient, cast: Cast) -> None:
    lab = _zone(api, cast.admin, "Lab", "Reliability", capacity=1)
    for actor in (cast.alice, cast.bob):
        assert _grant(api, cast.admin, lab, actor.id).status_code == 201

    assert _attempt(api, cast.alice, lab).json()["result"] == "Granted"
    full = _attempt(api, cast.bob, lab).json()
    assert (full["result"], full["reason"]) == ("Denied", "ZONE_AT_CAPACITY")

    exit_ = _attempt(api, cast.alice, lab, direction="Exit").json()
    assert (exit_["result"], exit_["current_occupancy"]) == ("Granted", 0)
    assert _attempt(api, cast.bob, lab).json()["result"] == "Granted"
    # Exit never drives occupancy negative.
    _attempt(api, cast.bob, lab, direction="Exit")
    assert _attempt(api, cast.bob, lab, direction="Exit").json()["current_occupancy"] == 0


def test_personnel_cannot_attempt_as_someone_else(api: TestClient, cast: Cast) -> None:
    lobby = _zone(api, cast.admin, "Lobby", "Reliability")
    assert _grant(api, cast.admin, lobby, cast.bob.id).status_code == 201
    response = _attempt(api, cast.alice, lobby, subject_id=cast.bob.id)
    assert response.status_code == 403
    visitor = _attempt(api, cast.alice, lobby, subject_type="Visitor", subject_id=cast.bob.id)
    assert visitor.status_code == 403


def test_clearance_downgrade_and_deactivation_deny_existing_grants(
    api: TestClient, cast: Cast, owner_engine: Engine
) -> None:
    ops = _zone(api, cast.admin, "Ops", "Secret_Level_II")
    assert _patch_user(api, cast.admin, cast.bob.id, clearance="Secret_Level_II").status_code == 200
    assert _grant(api, cast.admin, ops, cast.bob.id).status_code == 201
    assert _attempt(api, cast.officer, ops, subject_id=cast.bob.id).json()["result"] == "Granted"

    assert _patch_user(api, cast.admin, cast.bob.id, clearance="Reliability").status_code == 200
    downgraded = _attempt(api, cast.officer, ops, subject_id=cast.bob.id).json()
    assert downgraded["reason"] == "INSUFFICIENT_CLEARANCE"

    assert _patch_user(api, cast.admin, cast.bob.id, is_active=False).status_code == 200
    inactive = _attempt(api, cast.officer, ops, subject_id=cast.bob.id).json()
    assert (inactive["result"], inactive["reason"]) == ("Denied", "SUBJECT_INACTIVE")


def test_revoked_and_expired_grants_are_denied(
    api: TestClient, cast: Cast, owner_engine: Engine
) -> None:
    lobby = _zone(api, cast.admin, "Lobby", "Reliability")
    grant = _grant(api, cast.admin, lobby, cast.alice.id).json()
    api.post(f"{V1}/zones/{lobby}/grants/{grant['id']}/revoke", headers=cast.admin.headers)
    assert _attempt(api, cast.alice, lobby).json()["reason"] == "GRANT_REVOKED"

    # A fresh grant supersedes the revoked one.
    assert _grant(api, cast.admin, lobby, cast.bob.id).status_code == 201
    with owner_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE zone_access_grants SET created_at = now() - interval '2 days', "
                "expires_at = now() - interval '1 day' WHERE user_id = :id"
            ),
            {"id": cast.bob.id},
        )
    assert _attempt(api, cast.bob, lobby).json()["reason"] == "GRANT_EXPIRED"


def test_admin_has_no_policy_bypass(api: TestClient, cast: Cast) -> None:
    vault = _zone(api, cast.admin, "Vault", "Top_Secret")
    response = _attempt(api, cast.admin, vault).json()
    assert (response["result"], response["reason"]) == ("Denied", "NO_GRANT")


def test_unknown_subject_is_denied_and_recorded(
    api: TestClient, cast: Cast, owner_engine: Engine
) -> None:
    lobby = _zone(api, cast.admin, "Lobby", "Reliability")
    ghost = str(uuid.uuid4())
    response = _attempt(api, cast.officer, lobby, subject_id=ghost).json()
    assert (response["result"], response["reason"]) == ("Denied", "UNKNOWN_SUBJECT")
    visitor = _attempt(api, cast.officer, lobby, subject_type="Visitor", subject_id=ghost).json()
    assert visitor["reason"] == "UNKNOWN_SUBJECT"
    assert [e[2] for e in _events(owner_engine)] == ["UNKNOWN_SUBJECT", "UNKNOWN_SUBJECT"]


def test_access_attempt_input_errors(api: TestClient, cast: Cast) -> None:
    lobby = _zone(api, cast.admin, "Lobby", "Reliability")
    assert _attempt(api, cast.alice, str(uuid.uuid4())).status_code == 404
    assert _attempt(api, cast.officer, lobby, subject_type="Visitor").status_code == 422
    assert _attempt(api, cast.alice, lobby, direction="Sideways").status_code == 422
    assert api.post(f"{V1}/zones/{lobby}/access-attempt", json={}).status_code == 401


def test_visitor_access_end_to_end(api: TestClient, cast: Cast, owner_engine: Engine) -> None:
    lobby = _zone(api, cast.admin, "Lobby", "Reliability")
    ops = _zone(api, cast.admin, "Ops", "Secret_Level_II")
    with owner_engine.begin() as conn:
        visitor_id = conn.execute(
            text(
                "INSERT INTO visitors (full_name, visitor_type, host_user_id, status, "
                "visit_start, visit_end) VALUES ('Guest', 'Visitor', :host, 'Approved', "
                "now() - interval '1 hour', now() + interval '1 hour') RETURNING id::text"
            ),
            {"host": cast.alice.id},
        ).scalar_one()

    refused = api.post(
        f"{V1}/zones/{ops}/grant",
        json={"visitor_id": visitor_id, "expires_at": _future()},
        headers=cast.officer.headers,
    )
    assert refused.status_code == 422
    assert refused.json()["detail"]["reason"] == "INSUFFICIENT_CLEARANCE"

    granted = api.post(
        f"{V1}/zones/{lobby}/grant",
        json={"visitor_id": visitor_id, "expires_at": _future()},
        headers=cast.officer.headers,
    )
    assert granted.status_code == 201
    entry = _attempt(api, cast.officer, lobby, subject_type="Visitor", subject_id=visitor_id)
    assert entry.json()["result"] == "Granted"

    with owner_engine.begin() as conn:
        conn.execute(text("UPDATE visitors SET status = 'Expired'"))
    late = _attempt(api, cast.officer, lobby, subject_type="Visitor", subject_id=visitor_id)
    assert late.json()["reason"] == "VISITOR_NOT_APPROVED"


# --- Audit chain linkage ------------------------------------------------------------------


def test_audit_entries_form_a_linked_chain(
    api: TestClient, cast: Cast, owner_engine: Engine
) -> None:
    lobby = _zone(api, cast.admin, "Lobby", "Reliability")
    _grant(api, cast.admin, lobby, cast.alice.id)
    _attempt(api, cast.alice, lobby)

    log = _audit(owner_engine)
    assert len(log) >= 7
    assert log[0]["prev_hash"] == GENESIS_HASH
    for previous, current in itertools.pairwise(log):
        assert current["prev_hash"] == previous["entry_hash"]
    assert len({e["entry_hash"] for e in log}) == len(log)

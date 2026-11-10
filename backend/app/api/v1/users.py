"""API v1 routes: users.

- Admin: list, read and update any user (name, role, clearance, activation).
- SecurityOfficer: read-only access to every user.
- Personnel: may read only their own record. Asking for anyone else answers 404 whether or
  not the id exists, so the endpoint is not an oracle for valid user ids (IDOR).

Guard rails on updates: an Admin may not change their own role, clearance or activation
(no self-demotion, no self-deactivation, no self-elevation), and only an Admin may assign the
Admin role or Top_Secret clearance. Every change is written to the audit log in the same
transaction as the change itself.
"""

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

from app.core.deps import CurrentUser, DbSession, RedisClient, require_roles
from app.models.enums import Clearance, Role
from app.models.user import User
from app.schemas.user import UserRead, UserUpdate
from app.services import audit_chain, auth_service

router = APIRouter(prefix="/users", tags=["users"])

USER_NOT_FOUND = "User not found"
SELF_PRIVILEGE_CHANGE = "Admins cannot change their own role, clearance or activation"

Reader = Annotated[User, Depends(require_roles(Role.Admin, Role.SecurityOfficer))]
AdminUser = Annotated[User, Depends(require_roles(Role.Admin))]


def assert_may_assign(actor: User, role: Role | None, clearance: Clearance | None) -> None:
    """Only an Admin may hand out the Admin role or Top_Secret clearance."""
    if actor.role == Role.Admin:
        return
    if role == Role.Admin or clearance == Clearance.Top_Secret:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient privileges")


@router.get("", response_model=list[UserRead])
def list_users(_: Reader, db: DbSession) -> list[User]:
    return list(db.scalars(select(User).order_by(User.created_at, User.id)))


@router.get("/{user_id}", response_model=UserRead)
def get_user(user_id: uuid.UUID, actor: CurrentUser, db: DbSession) -> User:
    if actor.role == Role.Personnel and actor.id != user_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, USER_NOT_FOUND)
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, USER_NOT_FOUND)
    return user


@router.patch("/{user_id}", response_model=UserRead)
def update_user(
    user_id: uuid.UUID, payload: UserUpdate, actor: AdminUser, db: DbSession, redis: RedisClient
) -> User:
    assert_may_assign(actor, payload.role, payload.clearance)
    user = db.get(User, user_id, with_for_update=True)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, USER_NOT_FOUND)

    changes: dict[str, Any] = {}
    if payload.full_name is not None and payload.full_name != user.full_name:
        changes["full_name"] = {"from": user.full_name, "to": payload.full_name}
    if payload.role is not None and payload.role != user.role:
        changes["role"] = {"from": user.role, "to": payload.role}
    if payload.clearance is not None and payload.clearance != user.clearance:
        changes["clearance"] = {"from": user.clearance, "to": payload.clearance}
    if payload.is_active is not None and payload.is_active != user.is_active:
        changes["is_active"] = {"from": user.is_active, "to": payload.is_active}

    if user.id == actor.id and changes.keys() & {"role", "clearance", "is_active"}:
        db.rollback()
        raise HTTPException(status.HTTP_403_FORBIDDEN, SELF_PRIVILEGE_CHANGE)
    if not changes:
        db.rollback()
        return user

    if "full_name" in changes:
        user.full_name = changes["full_name"]["to"]
    if "role" in changes:
        user.role = changes["role"]["to"]
    if "clearance" in changes:
        user.clearance = changes["clearance"]["to"]
    if "is_active" in changes:
        user.is_active = changes["is_active"]["to"]
    audit_chain.append(db, actor.id, "user.update", f"users/{user.id}", {"changes": changes})
    db.commit()

    if changes.get("is_active", {}).get("to") is False:
        # Requests already re-check is_active against the DB; this also kills refresh tokens.
        auth_service.revoke_all_sessions(redis, user.id)
    return user

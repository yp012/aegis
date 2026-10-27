"""Tests for database plumbing that do not require a live database."""

from sqlalchemy.orm import Session

from app.db.base import NAMING_CONVENTION, Base
from app.db.session import SessionLocal, engine, get_db


def test_base_metadata_uses_naming_convention() -> None:
    assert dict(Base.metadata.naming_convention).items() >= NAMING_CONVENTION.items()


def test_session_factory_bound_to_engine() -> None:
    assert SessionLocal.kw["bind"] is engine


def test_get_db_yields_session_and_closes() -> None:
    gen = get_db()
    db = next(gen)
    assert isinstance(db, Session)
    gen.close()
    assert not db.in_transaction()

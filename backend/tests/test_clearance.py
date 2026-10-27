"""Unit tests for the Clearance ordering helper."""

import itertools

import pytest
from sqlalchemy import Enum

from app.models import User, Visitor, Zone
from app.models.enums import Clearance

ORDERED = [Clearance.Reliability, Clearance.Secret_Level_II, Clearance.Top_Secret]


def test_tier_values_are_explicit() -> None:
    assert [c.value for c in ORDERED] == [1, 2, 3]
    assert sorted(Clearance) == ORDERED


def test_strict_ordering() -> None:
    assert Clearance.Reliability < Clearance.Secret_Level_II < Clearance.Top_Secret
    assert max(Clearance) is Clearance.Top_Secret
    assert min(Clearance) is Clearance.Reliability


@pytest.mark.parametrize(
    ("held", "required"),
    list(itertools.product(ORDERED, repeat=2)),
)
def test_satisfies_matrix(held: Clearance, required: Clearance) -> None:
    expected = ORDERED.index(held) >= ORDERED.index(required)
    assert held.satisfies(required) is expected


def test_satisfies_is_reflexive() -> None:
    assert all(c.satisfies(c) for c in Clearance)


@pytest.mark.parametrize("bad", [2, "Top_Secret", None, 2.0])
def test_satisfies_rejects_non_clearance(bad: object) -> None:
    with pytest.raises(TypeError):
        Clearance.Top_Secret.satisfies(bad)  # type: ignore[arg-type]


@pytest.mark.parametrize("clearance", ORDERED)
def test_parse_round_trips_canonical_label(clearance: Clearance) -> None:
    assert Clearance.parse(clearance.name) is clearance


@pytest.mark.parametrize("label", ["top_secret", "TopSecret", "3", ""])
def test_parse_rejects_unknown_labels(label: str) -> None:
    with pytest.raises(ValueError, match="unknown clearance level"):
        Clearance.parse(label)


@pytest.mark.parametrize(
    "column",
    [User.__table__.c.clearance, Zone.__table__.c.min_clearance, Visitor.__table__.c.clearance],
)
def test_pg_enum_label_order_matches_python_order(column: object) -> None:
    # PostgreSQL orders enum values by declaration, so DB-side >= agrees with satisfies().
    col_type = column.type  # type: ignore[attr-defined]
    assert isinstance(col_type, Enum)
    assert col_type.name == "clearance"
    assert list(col_type.enums) == [c.name for c in ORDERED]

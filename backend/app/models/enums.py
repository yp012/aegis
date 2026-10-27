"""Domain enumerations persisted as native PostgreSQL enum types.

Member names are the canonical labels stored in the database.
"""

import enum
from typing import Self


class Role(enum.StrEnum):
    Admin = "Admin"
    SecurityOfficer = "SecurityOfficer"
    Personnel = "Personnel"


class Clearance(enum.IntEnum):
    """Ordered clearance tiers. Higher value means broader access.

    The PostgreSQL enum is declared in the same order, so ``ORDER BY`` and ``>=``
    on the column agree with the Python ordering.
    """

    Reliability = 1
    Secret_Level_II = 2
    Top_Secret = 3

    def satisfies(self, required: "Clearance") -> bool:
        """Return True if this clearance meets or exceeds ``required``.

        Prefer this over raw ``>=`` so call sites read as policy, and so a stray
        ``int`` or string cannot silently be compared against a clearance.
        """
        if not isinstance(required, Clearance):
            raise TypeError(f"required must be a Clearance, got {type(required).__name__}")
        return self.value >= required.value

    @classmethod
    def parse(cls, label: str) -> Self:
        """Look up a clearance by its canonical label (e.g. ``"Top_Secret"``)."""
        try:
            return cls[label]
        except KeyError as exc:
            raise ValueError(f"unknown clearance level: {label!r}") from exc


class VisitorType(enum.StrEnum):
    Visitor = "Visitor"
    IT_Contractor = "IT_Contractor"


class VisitorStatus(enum.StrEnum):
    Pending = "Pending"
    Approved = "Approved"
    Denied = "Denied"
    Expired = "Expired"


class SubjectType(enum.StrEnum):
    User = "User"
    Visitor = "Visitor"


class AccessResult(enum.StrEnum):
    Granted = "Granted"
    Denied = "Denied"

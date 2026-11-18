"""Persistence for lab registrations and bridge into the policy LabRegistry."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

from ..docker.labs import LabProfile
from ..policy.gateway import LabRegistry
from .db import Database


@dataclass(frozen=True)
class LabRegistration:
    id: str
    profile: LabProfile
    registered_at: datetime


class LabStore:
    """Persisted lab registrations (lab_registrations table)."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def register(self, profile: LabProfile) -> LabRegistration:
        reg = LabRegistration(
            id=f"lab_{profile.name}",
            profile=profile,
            registered_at=datetime.now(),
        )
        self._db.conn.execute(
            "INSERT OR REPLACE INTO lab_registrations (id, registered_at, payload)"
            " VALUES (?, ?, ?)",
            (
                reg.id,
                reg.registered_at.isoformat(),
                json.dumps(
                    {
                        "name": profile.name,
                        "subnet_cidr": profile.subnet_cidr,
                        "profile": json.loads(profile.model_dump_json()),
                    }
                ),
            ),
        )
        self._db.conn.commit()
        return reg

    def unregister(self, name: str) -> None:
        self._db.conn.execute("DELETE FROM lab_registrations WHERE id = ?", (f"lab_{name}",))
        self._db.conn.commit()

    def list(self) -> list[LabRegistration]:
        rows = self._db.conn.execute(
            "SELECT id, registered_at, payload FROM lab_registrations ORDER BY id"
        ).fetchall()
        result: list[LabRegistration] = []
        for row in rows:
            data = json.loads(row["payload"])
            result.append(
                LabRegistration(
                    id=row["id"],
                    profile=LabProfile.model_validate(data["profile"]),
                    registered_at=datetime.fromisoformat(row["registered_at"]),
                )
            )
        return result

    def get(self, name: str) -> LabRegistration | None:
        row = self._db.conn.execute(
            "SELECT payload FROM lab_registrations WHERE id = ?", (f"lab_{name}",)
        ).fetchone()
        if not row:
            return None
        data = json.loads(row["payload"])
        return LabRegistration(
            id=f"lab_{name}",
            profile=LabProfile.model_validate(data["profile"]),
            registered_at=datetime.now(),
        )

    def policy_registry(self) -> LabRegistry:
        """Build the policy LabRegistry from persisted registrations."""
        registry = LabRegistry()
        for reg in self.list():
            registry.register_network(reg.profile.subnet_cidr)
        return registry

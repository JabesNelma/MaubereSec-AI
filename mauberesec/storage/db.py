"""SQLite persistence with ordered, versioned migrations.

Uses the stdlib sqlite3 driver with WAL journaling. Records are stored
as JSON payloads in typed tables (per TECHNICAL_ARCHITECTURE §10).
No API keys, passwords, cookies, or secret values are ever stored —
FindingRecord/AuditEventRecord validators redact on construction.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..paths import data_dir
from ..records import (
    AssessmentRecord,
    AuditEventRecord,
    FindingRecord,
    ToolRunRecord,
)

SCHEMA_VERSION = 1

_MIGRATIONS: dict[int, str] = {
    1: """
    CREATE TABLE IF NOT EXISTS assessments (
        id TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        mode TEXT NOT NULL,
        status TEXT NOT NULL,
        payload TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS scopes (
        assessment_id TEXT PRIMARY KEY REFERENCES assessments(id),
        sha256 TEXT NOT NULL,
        payload TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tool_runs (
        id TEXT PRIMARY KEY,
        assessment_id TEXT NOT NULL REFERENCES assessments(id),
        started_at TEXT NOT NULL,
        payload TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        assessment_id TEXT NOT NULL REFERENCES assessments(id),
        created_at TEXT NOT NULL,
        severity TEXT NOT NULL,
        payload TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_events (
        id TEXT PRIMARY KEY,
        assessment_id TEXT,
        timestamp TEXT NOT NULL,
        category TEXT NOT NULL,
        decision TEXT NOT NULL,
        payload TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS lab_registrations (
        id TEXT PRIMARY KEY,
        registered_at TEXT NOT NULL,
        payload TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_assessment ON audit_events(assessment_id);
    CREATE INDEX IF NOT EXISTS idx_findings_assessment ON findings(assessment_id);
    """,
}


class Database:
    """Thin, typed wrapper around the SQLite store."""

    def __init__(self, path: Path | str | None = None) -> None:
        if path is None:
            path = data_dir() / "mauberesec.sqlite3"
        self.path = Path(path)
        if self.path.is_dir():  # convenience: accept a directory
            self.path = self.path / "mauberesec.sqlite3"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.migrate()

    # -- migrations ----------------------------------------------------------

    def current_version(self) -> int:
        return int(self.conn.execute("PRAGMA user_version").fetchone()[0])

    def migrate(self) -> None:
        version = self.current_version()
        for target in sorted(_MIGRATIONS):
            if target > version:
                self.conn.executescript(_MIGRATIONS[target])
                self.conn.execute(f"PRAGMA user_version={target}")
                self.conn.commit()

    # -- writes ----------------------------------------------------------------

    def save_assessment(self, record: AssessmentRecord) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO assessments (id, created_at, mode, status, payload)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                record.id,
                record.created_at.isoformat(),
                record.mode.value,
                record.status,
                record.model_dump_json(),
            ),
        )
        self.conn.execute(
            "INSERT OR REPLACE INTO scopes (assessment_id, sha256, payload) VALUES (?, ?, ?)",
            (record.id, record.scope.sha256(), record.scope.model_dump_json()),
        )
        self.conn.commit()

    def save_tool_run(self, record: ToolRunRecord) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO tool_runs (id, assessment_id, started_at, payload)"
            " VALUES (?, ?, ?, ?)",
            (
                record.id,
                record.assessment_id,
                record.started_at.isoformat(),
                record.model_dump_json(),
            ),
        )
        self.conn.commit()

    def save_finding(self, record: FindingRecord) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO findings (id, assessment_id, created_at, severity, payload)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                record.id,
                record.assessment_id,
                record.created_at.isoformat(),
                record.severity.value,
                record.model_dump_json(),
            ),
        )
        self.conn.commit()

    def save_audit_event(self, record: AuditEventRecord) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO audit_events (id, assessment_id, timestamp,"
            " category, decision, payload) VALUES (?, ?, ?, ?, ?, ?)",
            (
                record.id,
                record.assessment_id,
                record.timestamp.isoformat(),
                record.category,
                record.decision,
                record.model_dump_json(),
            ),
        )
        self.conn.commit()

    # -- reads -------------------------------------------------------------------

    def list_assessments(self) -> Iterator[AssessmentRecord]:
        for row in self.conn.execute("SELECT payload FROM assessments ORDER BY created_at"):
            yield AssessmentRecord.model_validate_json(row["payload"])

    def get_assessment(self, assessment_id: str) -> AssessmentRecord | None:
        row = self.conn.execute(
            "SELECT payload FROM assessments WHERE id = ?", (assessment_id,)
        ).fetchone()
        return AssessmentRecord.model_validate_json(row["payload"]) if row else None

    def list_audit_events(self, assessment_id: str | None = None) -> list[AuditEventRecord]:
        if assessment_id is None:
            rows = self.conn.execute(
                "SELECT payload FROM audit_events ORDER BY timestamp"
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT payload FROM audit_events WHERE assessment_id = ? ORDER BY timestamp",
                (assessment_id,),
            ).fetchall()
        return [AuditEventRecord.model_validate_json(r["payload"]) for r in rows]

    def list_findings(self, assessment_id: str) -> list[FindingRecord]:
        rows = self.conn.execute(
            "SELECT payload FROM findings WHERE assessment_id = ? ORDER BY created_at",
            (assessment_id,),
        ).fetchall()
        return [FindingRecord.model_validate_json(r["payload"]) for r in rows]

    # -- lifecycle -----------------------------------------------------------------

    def close(self) -> None:
        self.conn.close()


def _json_dump(model: Any) -> str:
    return json.dumps(model.model_dump(mode="json"))

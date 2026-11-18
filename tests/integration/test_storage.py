"""Integration tests for SQLite persistence and migrations."""

from pathlib import Path

from mauberesec.records import (
    AssessmentRecord,
    AuditEventRecord,
    FindingRecord,
    Mode,
    Scope,
    ScopeTarget,
    Severity,
    TargetKind,
    ToolRunRecord,
)
from mauberesec.storage.db import SCHEMA_VERSION, Database


def make_db(tmp: str) -> Database:
    return Database(Path(tmp) / "t.sqlite3")


def make_assessment() -> AssessmentRecord:
    scope = Scope(
        mode=Mode.LOCAL_FILE,
        targets=(ScopeTarget(kind=TargetKind.REPO, value="/data/repo"),),
    )
    return AssessmentRecord(mode=scope.mode, scope=scope)


def test_migration_sets_version(tmp_path):
    db = Database(tmp_path / "a.sqlite3")
    assert db.current_version() == SCHEMA_VERSION
    db.close()


def test_rerun_migrations_idempotent(tmp_path):
    path = tmp_path / "b.sqlite3"
    db1 = Database(path)
    db1.save_assessment(make_assessment())
    db1.close()
    db2 = Database(path)
    assert db2.current_version() == SCHEMA_VERSION
    assert len(list(db2.list_assessments())) == 1
    db2.close()


def test_assessment_roundtrip(tmp_path):
    db = make_db(str(tmp_path))
    record = make_assessment()
    db.save_assessment(record)
    loaded = db.get_assessment(record.id)
    assert loaded is not None
    assert loaded.scope.sha256() == record.scope.sha256()
    assert db.get_assessment("asm_missing") is None
    db.close()


def test_audit_events_persisted_and_queryable(tmp_path):
    db = make_db(str(tmp_path))
    record = make_assessment()
    db.save_assessment(record)
    db.save_audit_event(
        AuditEventRecord(assessment_id=record.id, category="policy", decision="allow")
    )
    db.save_audit_event(AuditEventRecord(category="startup", decision="info"))
    assert len(db.list_audit_events(record.id)) == 1
    assert len(db.list_audit_events()) == 2
    db.close()


def test_findings_and_tool_runs_roundtrip(tmp_path):
    db = make_db(str(tmp_path))
    record = make_assessment()
    db.save_assessment(record)
    db.save_tool_run(ToolRunRecord(assessment_id=record.id, tool_name="static.semgrep"))
    db.save_finding(
        FindingRecord(
            assessment_id=record.id,
            title="Hardcoded secret",
            severity=Severity.HIGH,
        )
    )
    findings = db.list_findings(record.id)
    assert findings[0].title == "Hardcoded secret"
    assert findings[0].severity == Severity.HIGH
    db.close()

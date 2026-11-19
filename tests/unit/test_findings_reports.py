"""Findings verification, correlation, and report tests (v0.11)."""

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parents[1]))

from mauberesec.cli.app import app
from mauberesec.findings.correlate import correlate, correlation_key
from mauberesec.findings.schema import (
    FINDING_SCHEMA_VERSION,
    EvidenceItem,
    FindingSource,
    FindingV1,
)
from mauberesec.findings.verify import (
    VerificationError,
    apply_verdict,
    is_confirmable,
    verify_finding,
)
from mauberesec.records import (
    AssessmentRecord,
    Confidence,
    FindingRecord,
    Mode,
    Scope,
    ScopeTarget,
    Severity,
    TargetKind,
    ToolRunRecord,
    VerificationStatus,
)
from mauberesec.reports.generator import (
    build_report_document,
    render_markdown,
    report_schema,
    write_report,
)
from mauberesec.storage.db import Database

runner = CliRunner()
SECRET = "sk-proj-AbCdEfGh1234567890IjKlMnOpQrSt"  # noqa: S105 - fake test key


def make_finding(**overrides) -> FindingV1:
    base = {
        "id": "fnd_1",
        "title": "Missing security header: Content-Security-Policy",
        "severity": Severity.LOW,
        "confidence": Confidence.HIGH,
        "source": FindingSource.TOOL,
        "tool_name": "passive.http_headers",
        "evidence": [EvidenceItem(kind="http", locator="https://example.com/")],
        "remediation": "Add a CSP.",
    }
    base.update(overrides)
    return FindingV1(**base)


# --- verification rules --------------------------------------------------------


def test_llm_only_can_never_be_confirmed():
    llm = make_finding(
        source=FindingSource.LLM,
        tool_name=None,
        evidence=[EvidenceItem(kind="text", locator="model said so")],
    )
    verdict = verify_finding(llm, reproduced=True)  # even when "reproduced"
    assert verdict.status == VerificationStatus.NEEDS_REVIEW
    assert "LLM-only" in verdict.reason
    assert is_confirmable(apply_verdict(llm, verdict)) is False


def test_tool_backed_reproduced_is_confirmed():
    verdict = verify_finding(make_finding(), reproduced=True)
    assert verdict.status == VerificationStatus.CONFIRMED
    assert verdict.reproduced is True


def test_tool_backed_not_reproduced_is_marked():
    verdict = verify_finding(make_finding(), reproduced=False)
    assert verdict.status == VerificationStatus.NOT_REPRODUCIBLE


def test_no_locator_needs_review():
    finding = make_finding(evidence=[EvidenceItem(kind="note", locator="x")])
    finding = finding.model_copy(update={"evidence": []})
    verdict = verify_finding(finding, reproduced=True)
    assert verdict.status == VerificationStatus.NEEDS_REVIEW


def test_refutation_requires_deterministic_evidence():
    with pytest.raises(VerificationError, match="requires deterministic evidence"):
        verify_finding(make_finding(), refuted=True)
    verdict = verify_finding(
        make_finding(),
        refuted=True,
        refutation_evidence=[
            EvidenceItem(kind="http", locator="https://example.com/ re-check 404")
        ],
    )
    assert verdict.status == VerificationStatus.FALSE_POSITIVE


def test_finding_schema_is_versioned():
    assert make_finding().schema_version == FINDING_SCHEMA_VERSION
    assert "1.0" in FINDING_SCHEMA_VERSION


# --- correlation ---------------------------------------------------------------


def test_correlate_merges_same_issue_same_location_across_tools():
    """Two tools reporting the same issue at the same locator merge into one."""
    a = make_finding(id="fnd_a")
    b = make_finding(
        id="fnd_b",
        tool_name="other.tool",
        severity=Severity.MEDIUM,
        evidence=[EvidenceItem(kind="http", locator="https://example.com/")],
    )
    merged = correlate([a, b])
    assert len(merged) == 1
    assert merged[0].severity == Severity.MEDIUM  # most conservative wins
    tools = merged[0].tool_name or ""
    assert "other.tool" in tools and "passive.http_headers" in tools


def test_correlate_keeps_different_locations_separate():
    """Same issue class at two locations stays two findings (never over-merged)."""
    a = make_finding(id="fnd_a")
    b = make_finding(
        id="fnd_b",
        evidence=[EvidenceItem(kind="http", locator="https://example.com/admin")],
    )
    merged = correlate([a, b])
    assert len(merged) == 2


def test_correlation_key_strips_volatile_identifiers():
    one = make_finding(title="Vulnerable dependency: requests 2.19.0 — GHSA-x9j5")
    two = make_finding(title="Vulnerable dependency: requests 2.19.0 — GHSA-abc1")
    assert correlation_key(one) == correlation_key(two)
    assert len(correlate([one, two])) == 1


def test_distinct_findings_stay_distinct():
    a = make_finding(id="a")
    b = make_finding(id="b", title="Different issue")
    assert len(correlate([a, b])) == 2


# --- report generation ---------------------------------------------------------------


@pytest.fixture()
def populated_db(tmp_path):
    db = Database(tmp_path / "rep.sqlite3")
    scope = Scope(
        mode=Mode.LIVE_WHITE_HAT,
        targets=(ScopeTarget(kind=TargetKind.WEBSITE, value="example.com"),),
    )
    assessment = AssessmentRecord(
        mode=scope.mode,
        scope=scope,
        status="completed",
        authorization_reference="contract-1",
    )
    db.save_assessment(assessment)
    db.save_tool_run(
        ToolRunRecord(
            assessment_id=assessment.id,
            tool_name="passive.http_headers",
            exit_code=0,
            redacted_summary="ok",
        )
    )
    db.save_finding(
        FindingRecord(
            assessment_id=assessment.id,
            title="Missing security header: HSTS",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            tool_name="passive.http_headers",
            evidence=f"GET https://example.com/ -> 200 (token {SECRET} leaked here)",
            remediation="Add HSTS.",
        )
    )
    db.save_finding(
        FindingRecord(
            assessment_id=assessment.id,
            title="LLM-suggested suspicious pattern",
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            tool_name=None,  # no tool ⇒ LLM-style claim
            evidence="model claimed a weakness",
            remediation="Review manually.",
        )
    )
    yield db, assessment
    db.close()


def test_report_document_shape(populated_db):
    db, assessment = populated_db
    document = build_report_document(db, assessment)
    assert document["schema_version"] == FINDING_SCHEMA_VERSION
    assert document["assessment"]["mode"] == "live_white_hat"
    assert document["assessment"]["partial"] is False
    assert document["assessment"]["scope_sha256"] == assessment.scope.sha256()
    assert "passive.http_headers" in document["tooling"]["tools_used"]
    assert document["limitations"] and document["untested_areas"]
    assert document["summary"]["total_findings"] == 2


def test_report_contains_no_secrets(populated_db):
    db, assessment = populated_db
    document = build_report_document(db, assessment)
    blob = json.dumps(document)
    assert SECRET not in blob
    assert "[REDACTED" in blob
    markdown = render_markdown(document)
    assert SECRET not in markdown


def test_llm_claim_not_confirmed_in_report(populated_db):
    db, assessment = populated_db
    document = build_report_document(db, assessment)
    llm_finding = next(f for f in document["findings"] if f["source"] == "llm")
    assert llm_finding["verification"] != "confirmed"


def test_partial_report_marked(populated_db, tmp_path):
    db, assessment = populated_db
    db.save_assessment(assessment.model_copy(update={"status": "cancelled"}))
    bundle = write_report(db, db.get_assessment(assessment.id), tmp_path)
    assert bundle.partial is True
    assert "PARTIAL" in bundle.markdown_path.read_text()


def test_written_report_matches_shipped_schema(populated_db, tmp_path):
    db, assessment = populated_db
    bundle = write_report(db, assessment, tmp_path)
    document = json.loads(bundle.json_path.read_text())
    schema = report_schema()

    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(instance=document, schema=schema)
    # Architecture §11 layout
    assert (bundle.directory / "findings.json").is_file()
    assert (bundle.directory / "metadata.json").is_file()


def test_report_includes_every_required_section(populated_db, tmp_path):
    db, assessment = populated_db
    bundle = write_report(db, assessment, tmp_path)
    markdown = bundle.markdown_path.read_text()
    for section in (
        "## Summary",
        "## Tooling",
        "## Findings",
        "## Limitations",
        "## Untested areas",
    ):
        assert section in markdown
    assert "Scope hash" in markdown


def test_finding_missing_remediation_flagged(populated_db, tmp_path):
    db, assessment = populated_db
    db.save_finding(
        FindingRecord(
            assessment_id=assessment.id,
            title="No remediation provided",
            tool_name="passive.http_headers",
            evidence="observed",
            remediation="",
        )
    )
    bundle = write_report(db, assessment, tmp_path)
    assert "flagged as incomplete" in bundle.markdown_path.read_text()


# --- CLI --------------------------------------------------------------------------


def test_cli_history_and_report(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    db = Database(tmp_path / "mauberesec" / "mauberesec.sqlite3")
    scope = Scope(
        mode=Mode.LOCAL_FILE,
        targets=(ScopeTarget(kind=TargetKind.REPO, value="/data/repo"),),
    )
    assessment = AssessmentRecord(mode=scope.mode, scope=scope, status="completed")
    db.save_assessment(assessment)
    db.close()

    listed = runner.invoke(app, ["history"])
    assert listed.exit_code == 0
    assert assessment.id in listed.output

    shown = runner.invoke(app, ["assessment", "show", assessment.id])
    assert shown.exit_code == 0

    generated = runner.invoke(
        app, ["report", "generate", assessment.id, "--out", str(tmp_path / "out")]
    )
    assert generated.exit_code == 0
    assert (tmp_path / "out" / assessment.id / "report.json").is_file()

    missing = runner.invoke(app, ["report", "generate", "asm_nope"])
    assert missing.exit_code == 2


def test_cli_report_schema_command():
    result = runner.invoke(app, ["report", "schema"])
    assert result.exit_code == 0
    assert "findings" in result.output

"""Release-gate tests for v1.0 (docs present, version, JSON outputs, gates)."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from mauberesec import __version__  # noqa: E402
from mauberesec.cli.app import app  # noqa: E402

runner = CliRunner()


def test_version_is_1_0():
    assert __version__ == "1.0.0"
    result = runner.invoke(app, ["--version"])
    assert "1.0.0" in result.output


@pytest.mark.parametrize(
    "doc",
    [
        "docs/THREAT_MODEL.md",
        "docs/SECURITY_REVIEW.md",
        "docs/INSTALL.md",
        "docs/SUPPORT_MATRIX.md",
        "docs/DEPENDENCIES.md",
        "docs/CLI.md",
        "docs/PRD.md",
        "docs/ROADMAP.md",
        "docs/TECHNICAL_ARCHITECTURE.md",
        "docs/SECURITY_POLICY.md",
        "docs/TESTING_STRATEGY.md",
    ],
)
def test_required_docs_exist_and_are_substantive(doc):
    path = ROOT / doc
    assert path.is_file(), f"missing release document: {doc}"
    assert len(path.read_text(encoding="utf-8")) > 500, f"{doc} looks like a stub"


def test_threat_model_covers_core_boundaries():
    text = (ROOT / "docs/THREAT_MODEL.md").read_text(encoding="utf-8").lower()
    for concept in (
        "prompt-injection",
        "docker",
        "mcp",
        "redaction",
        "fail-closed",
        "residual risks",
    ):
        assert concept in text, f"threat model missing: {concept}"


def test_security_review_declares_no_unresolved_high_defects():
    text = (ROOT / "docs/SECURITY_REVIEW.md").read_text(encoding="utf-8")
    assert "No unresolved critical or high product security defects" in text
    # Every boundary section references tests as evidence.
    assert text.count("**Tests:**") >= 5


def test_support_matrix_matches_evidence_policy():
    text = (ROOT / "docs/SUPPORT_MATRIX.md").read_text(encoding="utf-8")
    assert "Not tested" in text, "unsupported platforms must not be claimed as verified"
    assert "Linux" in text and "Verified" in text


def test_cli_docs_list_exit_codes():
    text = (ROOT / "docs/CLI.md").read_text(encoding="utf-8")
    for code in ("`0`", "`1`", "`2`", "`3`", "`130`"):
        assert code in text, f"exit code {code} not documented"


def test_release_check_script_is_executable_and_complete():
    script = ROOT / "scripts/release_check.sh"
    assert script.is_file()
    text = script.read_text()
    for step in ("ruff", "mypy", "pytest", "docker build", "RELEASE GATE: PASS"):
        assert step in text, f"release gate missing step: {step}"


def test_doctor_json_output_is_machine_readable():
    result = runner.invoke(app, ["doctor", "--json"])
    payload = json.loads(result.output)
    assert payload["version"] == "1.0.0"
    assert isinstance(payload["checks"], list)
    assert all({"name", "ok", "detail"} <= set(c) for c in payload["checks"])


def test_history_json_output(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    from mauberesec.records import AssessmentRecord, Mode, Scope, ScopeTarget, TargetKind
    from mauberesec.storage.db import Database

    db = Database(tmp_path / "mauberesec" / "mauberesec.sqlite3")
    scope = Scope(
        mode=Mode.LOCAL_FILE,
        targets=(ScopeTarget(kind=TargetKind.REPO, value="/data/repo"),),
    )
    record = AssessmentRecord(mode=scope.mode, scope=scope, status="completed")
    db.save_assessment(record)
    db.close()

    result = runner.invoke(app, ["history", "--json"])
    payload = json.loads(result.output)
    assert payload[0]["id"] == record.id
    assert payload[0]["mode"] == "local_file"


def test_help_lists_all_documented_commands():
    result = runner.invoke(app, ["--help"])
    for command in (
        "doctor",
        "config",
        "models",
        "lab",
        "scan",
        "audit",
        "apk",
        "agent",
        "mcp",
        "report",
        "history",
        "assessment",
    ):
        assert command in result.output, f"command missing from help: {command}"


def test_full_suite_is_the_regression_gate():
    """The v1.0 gate is the test suite itself; assert it is discoverable."""
    result = subprocess.run(  # noqa: S603 - fixed argv
        [str(ROOT / ".venv/bin/pytest"), "--collect-only", "-q"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert result.returncode == 0, result.stderr[-500:]
    assert "tests collected" in result.stdout
    collected = int(result.stdout.strip().splitlines()[-1].split()[0])
    assert collected >= 270, f"regression suite shrank unexpectedly: {collected}"

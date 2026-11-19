"""Security tests for APK analysis: no execution, redaction, safe failure."""

import json
import sys
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parents[1]))
from helpers_axml import sample_manifest_axml

from mauberesec.cli.app import app
from mauberesec.tools.apk.validate import (
    ApkValidationError,
    validate_apk_path,
)

runner = CliRunner()

SECRET = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105 - AWS docs example


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    yield tmp_path


def make_apk(tmp_path: Path, name: str = "app.apk") -> Path:
    apk = tmp_path / name
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", sample_manifest_axml())
        zf.writestr("classes.dex", b"dex\n" + SECRET.encode() + b"\n")
    return apk


def test_cli_rejects_non_apk(tmp_path):
    fake = tmp_path / "fake.apk"
    fake.write_bytes(b"MZ" + b"\x00" * 100)
    result = runner.invoke(app, ["apk", "analyze", str(fake)])
    assert result.exit_code == 2
    assert "ZIP header" in result.output


def test_cli_rejects_missing(tmp_path):
    result = runner.invoke(app, ["apk", "analyze", str(tmp_path / "no.apk")])
    assert result.exit_code == 2


def test_cli_rejects_symlink(tmp_path):
    real = make_apk(tmp_path, "real.apk")
    link = tmp_path / "link.apk"
    link.symlink_to(real)
    with pytest.raises(ApkValidationError, match="symlink"):
        validate_apk_path(str(link))


def test_cli_metadata_only(tmp_path):
    apk = make_apk(tmp_path)
    result = runner.invoke(app, ["apk", "analyze", str(apk), "--metadata-only"])
    assert result.exit_code == 0
    assert apk.resolve().as_posix().split("/")[-1] in result.output or "SHA-256" in result.output


def test_secret_never_in_records(tmp_path, isolated_env):
    from mauberesec.paths import data_dir
    from mauberesec.records import AssessmentRecord, Mode, Scope, ScopeTarget, TargetKind
    from mauberesec.storage.db import Database
    from mauberesec.tools.apk.container.apk_analyzer import analyze_apk

    apk = make_apk(tmp_path)
    report = analyze_apk(str(apk), "ab" * 32)
    assert SECRET not in json.dumps(report)

    db = Database(data_dir() / "mauberesec.sqlite3")
    scope = Scope(
        mode=Mode.LOCAL_FILE,
        targets=(ScopeTarget(kind=TargetKind.APK, value=str(apk)),),
    )
    assessment = AssessmentRecord(mode=scope.mode, scope=scope)
    db.save_assessment(assessment)
    db.save_tool_run(
        __import__("mauberesec.records", fromlist=["ToolRunRecord"]).ToolRunRecord(
            assessment_id=assessment.id,
            tool_name="apk.static_review",
            exit_code=0,
            redacted_summary=json.dumps(report["manifest"])[:900],
        )
    )
    db.close()
    db2 = Database(data_dir() / "mauberesec.sqlite3")
    for record in db2.list_audit_events():
        assert SECRET not in record.details
    db2.close()


def test_size_cap_rejected(tmp_path, monkeypatch):
    import mauberesec.tools.apk.validate as v

    apk = make_apk(tmp_path)
    monkeypatch.setattr(v, "MAX_APK_BYTES", 10)
    with pytest.raises(ApkValidationError, match="size cap"):
        validate_apk_path(str(apk))

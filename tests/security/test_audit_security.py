"""Security tests for the audit command and scanner isolation."""

import json

import pytest
from typer.testing import CliRunner

from mauberesec.cli.app import app
from mauberesec.docker.client import DockerClient, DockerCommandError
from mauberesec.tools.source_audit.adapters import parse_gitleaks

runner = CliRunner()


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n")
    yield repo


def test_audit_rejects_missing_path(isolated_env):
    result = runner.invoke(app, ["audit", str(isolated_env.parent / "nope")])
    assert result.exit_code == 2


def test_audit_inventory_only(isolated_env):
    result = runner.invoke(app, ["audit", str(isolated_env), "--inventory-only"])
    assert result.exit_code == 0
    assert "local_file" in result.output
    assert "will NOT be executed" in result.output


def test_audit_gitleaks_secrets_never_persisted(isolated_env):
    """The gitleaks parser output stored via audit must never contain secrets."""
    from mauberesec.paths import data_dir
    from mauberesec.storage.db import Database

    findings = parse_gitleaks(
        json.dumps(
            [
                {
                    "RuleID": "aws-key",
                    "File": "creds.py",
                    "StartLine": 3,
                    "Secret": "AKIAIOSFODNN7EXAMPLE",
                }
            ]
        )
    )
    secret = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105 - AWS docs example, not real
    assert all(secret not in f.model_dump_json() for f in findings)

    # Persisted records stay clean (needs a parent assessment for the FK).
    from mauberesec.records import Mode, Scope, ScopeTarget, TargetKind

    db = Database(data_dir() / "mauberesec.sqlite3")
    scope = Scope(
        mode=Mode.LOCAL_FILE,
        targets=(ScopeTarget(kind=TargetKind.REPO, value=str(isolated_env)),),
    )
    from mauberesec.records import AssessmentRecord

    assessment = AssessmentRecord(mode=scope.mode, scope=scope)
    db.save_assessment(assessment)
    for f in findings:
        db.save_finding(f.model_copy(update={"assessment_id": assessment.id}))
    stored = db.list_findings(assessment.id)
    assert len(stored) == len(findings)
    assert all(secret not in f.model_dump_json() for f in stored)
    db.close()


def test_scanner_adapter_fixed_command(isolated_env):
    """Adapter commands are fixed constants — project content can't alter them."""
    from mauberesec.tools.source_audit.adapters import (
        GITLEAKS_SPEC,
        OSV_SPEC,
        SEMGREP_SPEC,
    )

    assert SEMGREP_SPEC.command[0] == "semgrep"
    assert SEMGREP_SPEC.command[1] == "--config"
    # Gitleaks uses a fixed sh -c script (scan to tmpfs, print JSON).
    assert GITLEAKS_SPEC.entrypoint == "sh"
    assert GITLEAKS_SPEC.command[0] == "-c"
    assert "--redact" in GITLEAKS_SPEC.command[1]
    assert OSV_SPEC.command[0] == "--json"

    all_specs = (SEMGREP_SPEC, GITLEAKS_SPEC, OSV_SPEC)
    # Commands are frozen constants, not callable/model-derived.
    for spec in all_specs:
        assert isinstance(spec.command, tuple)
    # Env is fixed too (semgrep needs a writable HOME).
    assert SEMGREP_SPEC.env == {"HOME": "/tmp"}  # noqa: S108 - container-internal


def test_scanner_env_is_not_project_controlled(isolated_env):
    """No adapter env/entrypoint may originate from repository files."""
    from mauberesec.tools.source_audit.adapters import (
        GITLEAKS_SPEC,
        OSV_SPEC,
        SEMGREP_SPEC,
    )

    for spec in (SEMGREP_SPEC, GITLEAKS_SPEC, OSV_SPEC):
        if spec.env:
            for key, value in spec.env.items():
                assert "=" not in key
                assert "\n" not in value
        if spec.entrypoint:
            assert spec.entrypoint in ("sh", None)


def test_run_scanner_rejects_relative_host_path(isolated_env):
    client = DockerClient(docker_path="")
    with pytest.raises(DockerCommandError, match="absolute"):
        client.run_scanner("alpine:3.20", ["true"], host_path="relative/path")


def test_general_run_still_rejects_ro_host_mount(isolated_env):
    client = DockerClient()
    with pytest.raises(DockerCommandError, match="forbidden"):
        client.run(["run", "-v", "/etc:/etc:ro", "alpine"])

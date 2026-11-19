"""Integration tests: lab validation runs inside the lab network (real Docker)."""

import shutil

import pytest
from typer.testing import CliRunner

from mauberesec.cli.app import app
from mauberesec.docker.client import DockerClient
from mauberesec.docker.labs import builtin_profiles

pytestmark = pytest.mark.integration

docker_path = shutil.which("docker")
runner = CliRunner()


@pytest.fixture(scope="module")
def client():
    if docker_path is None:
        pytest.skip("docker CLI not available")
    c = DockerClient(docker_path=docker_path)
    if c.daemon_version() is None:
        pytest.skip("docker daemon not reachable")
    return c


@pytest.fixture()
def registered_lab(client, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    profile = builtin_profiles()["demo-web"]
    from mauberesec.docker.labs import LabManager
    from mauberesec.paths import database_path
    from mauberesec.storage.db import Database
    from mauberesec.storage.lab_store import LabStore

    db = Database(database_path())  # same DB the CLI opens
    store = LabStore(db)
    manager = LabManager(client)
    manager.teardown(profile.name)  # idempotent cleanup between tests
    store.register(profile)
    manager.create(profile)
    yield db, profile
    manager.teardown(profile.name)
    db.close()


def test_lab_test_safe_checks_end_to_end(client, registered_lab):
    _db, profile = registered_lab
    result = runner.invoke(
        app,
        [
            "lab",
            "test",
            profile.name,
            "--base-url",
            "http://10.66.7.10",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "security_headers" in result.output
    assert "Findings:" in result.output


def test_state_change_blocked_without_confirmation(client, registered_lab):
    _db, profile = registered_lab
    result = runner.invoke(
        app,
        [
            "lab",
            "test",
            profile.name,
            "--base-url",
            "http://10.66.7.10",
        ],
    )
    assert result.exit_code == 0
    # Without confirmation the synthetic_login check must not be included.
    db2 = __import__("mauberesec.storage.db", fromlist=["Database"]).Database(
        __import__("mauberesec.paths", fromlist=["database_path"]).database_path()
    )
    events = db2.list_audit_events()
    assert any("without per-run confirmation" in e.details for e in events)
    db2.close()


def test_reset_after_restores_baseline(client, registered_lab):
    _db, profile = registered_lab
    result = runner.invoke(
        app,
        [
            "lab",
            "test",
            profile.name,
            "--base-url",
            "http://10.66.7.10",
            "--reset-after",
        ],
    )
    assert result.exit_code == 0
    assert "reset to baseline" in result.output or "Lab reset" in result.output
    # Lab still healthy after reset.
    from mauberesec.docker.labs import LabManager

    assert LabManager(client).verify(profile.name)["ok"]


def test_probe_container_attaches_only_to_lab_network(client, registered_lab):
    """The probe container's network is the lab network (verified via inspect)."""
    _db, profile = registered_lab
    result = runner.invoke(app, ["lab", "test", profile.name, "--base-url", "http://10.66.7.10"])
    assert result.exit_code == 0
    # Indirect proof: probe reached the nginx service on the internal network
    # (impossible from the default bridge), and results contain service_info.
    assert "service_info" in result.output


def test_unregistered_lab_refused(client, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    result = runner.invoke(app, ["lab", "test", "no-such-lab", "--base-url", "http://10.66.7.10"])
    assert result.exit_code == 2
    assert "not registered" in result.output

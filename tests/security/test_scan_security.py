"""Security tests for the scan command and passive assessment flow."""

import pytest
from typer.testing import CliRunner

from mauberesec.cli.app import app
from mauberesec.paths import data_dir
from mauberesec.storage.db import Database

runner = CliRunner()


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    # Redirect data dir so tests never touch the real database.
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    yield tmp_path


def test_live_scan_requires_authorization():
    result = runner.invoke(app, ["scan", "https://example.com"])
    assert result.exit_code == 2
    assert "--auth-reference" in result.output


def test_live_scan_requires_both_auth_fields():
    result = runner.invoke(app, ["scan", "https://example.com", "--auth-reference", "t-1"])
    assert result.exit_code == 2


def test_scan_rejects_private_live_target():
    result = runner.invoke(
        app,
        [
            "scan",
            "http://10.0.0.5/",
            "--auth-reference",
            "t-1",
            "--authorized-by",
            "owner",
        ],
    )
    assert result.exit_code == 1
    assert "forbidden address" in result.output


def test_scan_rejects_metadata_endpoint():
    result = runner.invoke(
        app,
        [
            "scan",
            "http://169.254.169.254/",
            "--auth-reference",
            "t-1",
            "--authorized-by",
            "owner",
        ],
    )
    assert result.exit_code == 1


def test_scan_rejects_invalid_url():
    result = runner.invoke(app, ["scan", "ftp://example.com"])
    assert result.exit_code == 2


def test_scan_lab_target_unregistered_blocked():
    result = runner.invoke(app, ["scan", "http://127.0.0.1:8080"])
    # 127.0.0.1 is not a registered lab -> live -> requires authorization.
    assert result.exit_code == 2
    assert "authorization" in result.output


def test_passive_only_requests(monkeypatch):
    """The checker must never issue anything but GET without cookies."""
    from mauberesec.tools.website.passive import PassiveHttpChecker

    seen: list[tuple[str, dict]] = []

    class SpyClient:
        def get(self, url, timeout=None):
            seen.append(("GET", {"url": url}))
            import httpx

            return httpx.Response(200, request=httpx.Request("GET", url))

        def close(self):
            pass

    checker = PassiveHttpChecker(transport=SpyClient())  # type: ignore[arg-type]
    checker.check("https://example.com/")
    assert all(method == "GET" for method, _ in seen)


def test_audit_trail_persisted_for_blocked_scan(isolated_env):
    result = runner.invoke(
        app,
        [
            "scan",
            "http://192.168.1.10/",
            "--auth-reference",
            "t-1",
            "--authorized-by",
            "owner",
        ],
    )
    assert result.exit_code == 1
    db = Database(data_dir() / "mauberesec.sqlite3")
    # Policy decision (assessment start allow) plus destination handling audited.
    events = db.list_audit_events()
    assert any(e.decision == "allow" for e in events)
    db.close()

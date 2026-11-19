"""Unit tests for lab test profiles and the probe script logic."""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))

from mauberesec.labs.container.lab_probe import (
    Probe,
    ProbeBudgetError,
    run_payload,
)
from mauberesec.labs.profiles import (
    SAFE_CHECKS,
    STATE_CHANGING_CHECKS,
    SYNTHETIC_PASSWORD,
    SYNTHETIC_USERNAME,
    build_probe_payload,
    default_profile,
)


def test_profile_defaults_and_gates():
    profile = default_profile("demo-web", "http://10.66.7.10")
    assert SAFE_CHECKS == tuple(profile.safe_checks())
    assert STATE_CHANGING_CHECKS == tuple(profile.state_changing_checks())
    with pytest.raises(ValueError, match="Unknown lab checks"):
        profile.model_copy(update={"checks": ("password_spray",)}).validate_checks()


def test_payload_synthetic_only():
    payload = json.loads(build_probe_payload(default_profile("l", "http://10.66.7.10"), True))
    assert payload["synthetic_username"] == SYNTHETIC_USERNAME
    assert payload["synthetic_password"] == SYNTHETIC_PASSWORD
    # Credentials are the fixed synthetic pair — never vendor defaults.
    assert payload["synthetic_username"] != "admin"
    assert "admin" not in (payload["synthetic_username"] + payload["synthetic_password"]).lower()


def test_payload_excludes_state_changing_without_confirmation():
    payload = json.loads(
        build_probe_payload(default_profile("l", "http://10.66.7.10"), include_state_changing=False)
    )
    assert "synthetic_login" not in payload["checks"]


# --- probe script against a local fixture server -----------------------------


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/admin":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<html><title>Admin</title></html>")
        elif self.path == "/redirect-out":
            self.send_response(302)
            self.send_header("Location", "https://93.184.216.34/")
            self.end_headers()
        elif self.path == "/login":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<html><title>Login</title></html>")
        else:
            self.send_response(200)
            self.send_header("X-Custom", "yes")
            self.end_headers()
            self.wfile.write(b"<html><title>Demo Lab</title>body</html>")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        # Auth enforced: wrong synthetic credentials are rejected.
        self.send_response(401)
        self.end_headers()
        self.wfile.write(b"unauthorized")

    def log_message(self, *args) -> None:  # silence
        return


@pytest.fixture(scope="module")
def fixture_server():
    server = HTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def make_probe(base_url: str, **overrides) -> Probe:
    payload = json.loads(
        build_probe_payload(default_profile("l", base_url), include_state_changing=True)
    )
    payload.update(overrides)
    return Probe(payload)


def test_service_info_and_headers(fixture_server):
    probe = make_probe(fixture_server)
    info = probe.check_service_info()
    assert info["ok"] and info["title"] == "Demo Lab"
    headers = probe.check_security_headers()
    assert headers["ok"]
    assert "content-security-policy" in headers["missing"]


def test_common_paths_finds_exposed_admin(fixture_server):
    probe = make_probe(fixture_server)
    result = probe.check_common_paths()
    exposed = {item["path"] for item in result["exposed"]}
    assert "/admin" in exposed


def test_synthetic_login_reports_enforcement(fixture_server):
    probe = make_probe(fixture_server)
    result = probe.check_synthetic_login()
    assert result["ok"]
    assert result["auth_enforced_somewhere"] is True
    assert all(a.get("synthetic_accepted") is not True for a in result["attempts"])


def test_out_of_lab_destination_blocked():
    probe = make_probe("http://93.184.216.34", lab_subnets=["10.66.7.0/24"])
    result = probe.request("http://93.184.216.34/")
    assert result is not None and "outside lab subnets" in result.get("error", "")


def test_request_budget_enforced(fixture_server):
    probe = make_probe(fixture_server, max_requests=2)
    with pytest.raises(ProbeBudgetError):
        for _ in range(5):
            probe.request(fixture_server + "/")


def test_run_payload_end_to_end(fixture_server):
    payload = build_probe_payload(default_profile("l", fixture_server), include_state_changing=True)
    report = run_payload(payload)
    checks = [r["check"] for r in report["results"]]
    assert set(checks) >= {"service_info", "security_headers", "common_paths", "synthetic_login"}

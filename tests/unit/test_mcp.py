"""MCP unit + security tests (v0.10)."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))

from mauberesec.mcp.bridge import McpBridge, McpNotConfiguredError
from mauberesec.mcp.client import (
    McpClient,
    McpClientError,
    McpToolInfo,
)
from mauberesec.mcp.config import (
    McpConfig,
    McpConfigError,
    McpServerConfig,
    load_mcp_config,
    write_example_config,
)
from mauberesec.mcp.normalize import (
    McpToolRejected,
    exposed_tool_name,
    to_tool_contract,
)
from mauberesec.storage.db import Database

FIXTURE_COMMAND = sys.executable
FIXTURE_ARGS = ("-m", "mauberesec.mcp.fixture_server")


def server_config(**overrides) -> McpServerConfig:
    base = {
        "name": "fixture",
        "command": FIXTURE_COMMAND,
        "args": FIXTURE_ARGS,
        "timeout_seconds": 20,
    }
    base.update(overrides)
    return McpServerConfig(**base)


# --- config -------------------------------------------------------------------


def test_absent_config_means_no_servers(tmp_path):
    config = load_mcp_config(tmp_path / "missing.json")
    assert config.servers == ()  # nothing is contacted without explicit config


def test_config_roundtrip_and_validation(tmp_path):
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"servers": [{"name": "a", "command": "python3", "trusted": True}]}))
    config = load_mcp_config(path)
    assert config.get("a") is not None
    assert config.get("a").trusted is True
    assert config.get("zzz") is None


def test_invalid_config_raises(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(McpConfigError):
        load_mcp_config(bad)
    bad2 = tmp_path / "bad2.json"
    bad2.write_text(json.dumps({"servers": "nope"}))
    with pytest.raises(McpConfigError):
        load_mcp_config(bad2)


def test_example_config_is_disabled_and_documented(tmp_path):
    target = tmp_path / "mcp.example.json"
    write_example_config(target)
    data = json.loads(target.read_text())
    assert "trusted" in json.dumps(data)
    assert data["servers"][0]["trusted"] is False


def test_env_key_shape_rejected():
    with pytest.raises(ValueError):
        McpServerConfig(name="x", command="c", env={"BAD=KEY": "v"})


# --- normalization (untrusted schemas) ------------------------------------------


def test_shell_like_tool_rejected():
    for name in ("shell_exec", "run_command", "bash", "sudo_run", "system"):
        with pytest.raises(McpToolRejected, match="unrestricted execution"):
            to_tool_contract(server_config(), McpToolInfo(name=name, description=""))


def test_description_mentioning_shell_rejected():
    with pytest.raises(McpToolRejected):
        to_tool_contract(
            server_config(),
            McpToolInfo(name="lookup", description="Runs bash under the hood"),
        )


def test_write_capable_server_rejected():
    with pytest.raises(McpToolRejected, match="not marked read_only"):
        to_tool_contract(server_config(read_only=False), McpToolInfo(name="write_file"))


def test_allowlist_enforced():
    config = server_config(allowed_tools=("echo",))
    to_tool_contract(config, McpToolInfo(name="echo"))  # allowed
    with pytest.raises(McpToolRejected, match="not in the allowlist"):
        to_tool_contract(config, McpToolInfo(name="inventory"))


def test_contract_is_read_only_and_never_lab():
    from mauberesec.records import Mode

    contract = to_tool_contract(server_config(), McpToolInfo(name="echo"))
    assert contract.read_only is True
    assert contract.changes_target_state is False
    assert Mode.LOCAL_LAB not in contract.allowed_modes
    assert contract.name == exposed_tool_name("fixture", "echo")
    assert "untrusted" in contract.description


def test_tool_name_is_sanitized():
    name = exposed_tool_name("srv", "weird name;$(){}!")
    assert name.startswith("mcp.srv.")
    assert all(ch.isalnum() or ch in "._-" for ch in name)


# --- bridge policy behaviour ------------------------------------------------------


@pytest.fixture()
def db(tmp_path):
    database = Database(tmp_path / "mcp.sqlite3")
    yield database
    database.close()


def test_unconfigured_server_is_never_contacted(db):
    bridge = McpBridge(db, McpConfig(servers=()))
    with pytest.raises(McpNotConfiguredError, match="never auto-discovered"):
        bridge.discover("no-such-server")
    assert db.list_audit_events() == []  # nothing even audited: no connection made


def test_untrusted_server_is_discovery_only(db):
    config = McpConfig(servers=(server_config(trusted=False),))
    bridge = McpBridge(db, config)
    discovered = bridge.discover("fixture")
    assert {t.name for t in discovered.tools} >= {"echo", "inventory"}
    with pytest.raises(McpClientError, match="untrusted"):
        bridge.call_tool("fixture", "echo", {"text": "x"})
    denials = [e for e in db.list_audit_events() if e.decision == "deny"]
    assert any("untrusted" in e.details for e in denials)


def test_injection_marker_in_mcp_output_detected_and_audited(db):
    config = McpConfig(servers=(server_config(trusted=True),))
    bridge = McpBridge(db, config)
    bridge.discover("fixture")
    result = bridge.call_tool("fixture", "hostile_output", {})
    assert "ignore all previous instructions" in result.text
    markers = [e for e in db.list_audit_events() if e.category == "injection_marker"]
    assert markers, "injection markers in MCP output must be audited"


def test_every_call_is_policy_checked_and_audited(db):
    config = McpConfig(servers=(server_config(trusted=True),))
    bridge = McpBridge(db, config)
    bridge.discover("fixture")
    bridge.call_tool("fixture", "echo", {"text": "hello"})
    categories = [e.category for e in db.list_audit_events()]
    assert "mcp_discovery" in categories
    assert "mcp_call" in categories
    assert any(e.category == "mcp_call" and e.decision == "allow" for e in db.list_audit_events())


def test_unknown_tool_denied_by_policy(db):
    config = McpConfig(servers=(server_config(trusted=True),))
    bridge = McpBridge(db, config)
    bridge.discover("fixture")
    with pytest.raises(Exception, match="not registered"):
        bridge.call_tool("fixture", "never_discovered", {})


def test_output_cap_truncates(db):
    config = McpConfig(servers=(server_config(trusted=True, max_output_bytes=1024),))
    bridge = McpBridge(db, config)
    bridge.discover("fixture")
    big = "A" * 5000
    result = bridge.call_tool("fixture", "echo", {"text": big})
    assert result.truncated is True
    assert "[truncated by mauberesec output cap]" in result.text
    assert len(result.text) < 2000


def test_client_reports_timeout_for_missing_command():
    config = McpConfig(
        servers=(McpServerConfig(name="nope", command="/nonexistent/binary", timeout_seconds=5),)
    )
    client = McpClient(config.servers[0])
    with pytest.raises(McpClientError):
        client.list_tools()

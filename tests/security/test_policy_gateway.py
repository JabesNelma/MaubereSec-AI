"""Security tests for the deterministic policy gateway.

Covers the v0.2 acceptance criteria:
- Missing authorization blocks live assessment.
- Local Lab mode cannot be enabled from a CLI flag alone.
- Unknown target classification fails closed to Live restrictions.
- Audit events are persisted for every decision.
"""

from datetime import UTC, datetime, timedelta

import pytest

from mauberesec.policy.gateway import (
    LabRegistry,
    PolicyDenied,
    PolicyGateway,
    classify_target,
)
from mauberesec.records import (
    AuthorizationRecord,
    Mode,
    Scope,
    ScopeTarget,
    TargetKind,
)
from mauberesec.storage.db import Database
from mauberesec.tools.registry import ToolRegistry, UnknownToolError, default_registry


def make_gateway(tmp_path, labs: LabRegistry | None = None, registry: ToolRegistry | None = None):
    db = Database(tmp_path / "policy.sqlite3")
    labs = labs or LabRegistry()
    gw = PolicyGateway(db, registry or default_registry(), labs)
    return db, gw


def live_scope(value: str = "example.com") -> Scope:
    return Scope(
        mode=Mode.LIVE_WHITE_HAT, targets=(ScopeTarget(kind=TargetKind.WEBSITE, value=value),)
    )


def lab_scope(value: str = "10.66.0.5:8080") -> Scope:
    return Scope(mode=Mode.LOCAL_LAB, targets=(ScopeTarget(kind=TargetKind.WEBSITE, value=value),))


def valid_auth(scope: Scope) -> AuthorizationRecord:
    return AuthorizationRecord(
        reference="contract-1",
        scope_sha256=scope.sha256(),
        authorized_by="owner@example.com",
        valid_until=datetime.now(UTC) + timedelta(hours=2),
    )


# --- mode classification -------------------------------------------------------


def test_localhost_alone_is_not_a_lab():
    assert classify_target("localhost", LabRegistry()) == Mode.LIVE_WHITE_HAT
    assert classify_target("127.0.0.1", LabRegistry()) == Mode.LIVE_WHITE_HAT


def test_private_ip_unregistered_fails_closed():
    assert classify_target("10.66.0.5", LabRegistry()) == Mode.LIVE_WHITE_HAT


def test_unknown_hostname_fails_closed():
    assert classify_target("intranet.local", LabRegistry()) == Mode.LIVE_WHITE_HAT


def test_registered_network_grants_lab():
    labs = LabRegistry()
    labs.register_network("10.66.0.0/24")
    assert classify_target("10.66.0.5", labs) == Mode.LOCAL_LAB
    # Outside the registered subnet still fails closed.
    assert classify_target("10.66.1.5", labs) == Mode.LIVE_WHITE_HAT


def test_registered_hostname_grants_lab():
    labs = LabRegistry()
    labs.register_host("vuln-app.local")
    assert classify_target("vuln-app.local", labs) == Mode.LOCAL_LAB


# --- authorization enforcement ---------------------------------------------------


def test_missing_authorization_blocks_live(tmp_path):
    db, gw = make_gateway(tmp_path)
    with pytest.raises(PolicyDenied, match="authorization record"):
        gw.authorize_assessment(live_scope(), None)
    events = db.list_audit_events()
    assert any(e.decision == "deny" and e.category == "authorization" for e in events)


def test_scope_mismatch_blocks_live(tmp_path):
    _, gw = make_gateway(tmp_path)
    auth = valid_auth(live_scope("example.com"))
    with pytest.raises(PolicyDenied, match="scope hash"):
        gw.authorize_assessment(live_scope("other.example.com"), auth)


def test_expired_authorization_blocks_live(tmp_path):
    _, gw = make_gateway(tmp_path)
    scope = live_scope()
    expired = valid_auth(scope).model_copy(
        update={"valid_until": datetime.now(UTC) - timedelta(hours=1)}
    )
    with pytest.raises(PolicyDenied, match="expired"):
        gw.authorize_assessment(scope, expired)


def test_valid_authorization_allows_live(tmp_path):
    db, gw = make_gateway(tmp_path)
    scope = live_scope()
    record = gw.authorize_assessment(scope, valid_auth(scope))
    assert record.authorization_reference == "contract-1"
    assert any(e.decision == "allow" for e in db.list_audit_events(record.id))


# --- lab flag cannot bypass registration -----------------------------------------


def test_mode_lab_flag_cannot_bypass_lab_registration(tmp_path):
    _, gw = make_gateway(tmp_path)  # empty lab registry
    with pytest.raises(PolicyDenied, match="not a registered local lab"):
        gw.authorize_assessment(lab_scope("127.0.0.1:8080"), None)


def test_lab_scope_allowed_when_registered(tmp_path):
    labs = LabRegistry()
    labs.register_network("10.66.0.0/24")
    _, gw = make_gateway(tmp_path, labs=labs)
    record = gw.authorize_assessment(lab_scope(), None)
    assert record.mode == Mode.LOCAL_LAB


# --- tool call policy --------------------------------------------------------------


def test_agent_cannot_invent_tools(tmp_path):
    labs = LabRegistry()
    labs.register_network("10.66.0.0/24")
    _, gw = make_gateway(tmp_path, labs=labs)
    record = gw.authorize_assessment(lab_scope(), None)
    with pytest.raises(PolicyDenied, match="not registered"):
        gw.check_tool_call(record, "shell.rm", "10.66.0.5:8080")


def test_tool_mode_restriction_enforced(tmp_path):
    _, gw = make_gateway(tmp_path)
    scope = live_scope("example.com")
    record = gw.authorize_assessment(scope, valid_auth(scope))
    # lab-only tool must be denied in live mode
    with pytest.raises(PolicyDenied, match="not allowed in mode live_white_hat"):
        gw.check_tool_call(record, "lab.recon", "example.com")


def test_tool_target_out_of_scope_denied(tmp_path):
    labs = LabRegistry()
    labs.register_network("10.66.0.0/24")
    _, gw = make_gateway(tmp_path, labs=labs)
    record = gw.authorize_assessment(lab_scope("10.66.0.5:8080"), None)
    with pytest.raises(PolicyDenied, match="outside the assessment scope"):
        gw.check_tool_call(record, "lab.recon", "10.66.0.9:8080")


def test_state_changing_tool_requires_confirmation(tmp_path):
    labs = LabRegistry()
    labs.register_network("10.66.0.0/24")
    _, gw = make_gateway(tmp_path, labs=labs)
    record = gw.authorize_assessment(lab_scope(), None)
    with pytest.raises(PolicyDenied, match="explicit per-run confirmation"):
        gw.check_tool_call(record, "lab.controlled_validation", "10.66.0.5:8080")
    # With confirmation it is allowed (lab mode only).
    contract = gw.check_tool_call(
        record, "lab.controlled_validation", "10.66.0.5:8080", confirmed_state_change=True
    )
    assert contract.changes_target_state


def test_every_decision_audited(tmp_path):
    db, gw = make_gateway(tmp_path)
    scope = live_scope()
    record = gw.authorize_assessment(scope, valid_auth(scope))
    gw.check_tool_call(record, "passive.http_headers", "example.com")
    events = db.list_audit_events(record.id)
    assert len(events) == 2  # start allow + tool allow
    assert all(e.decision in ("allow", "deny") for e in events)


def test_registry_unknown_tool_error():
    registry = ToolRegistry()
    with pytest.raises(UnknownToolError):
        registry.get("nope")

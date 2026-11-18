"""Unit tests for record schemas, paths, and budgets."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from mauberesec.paths import config_dir, data_dir, database_path
from mauberesec.records import (
    LAB_BUDGET,
    LIVE_BUDGET,
    AuthorizationRecord,
    Mode,
    ResourceBudget,
    Scope,
    ScopeTarget,
    TargetKind,
)


def make_scope(mode: Mode = Mode.LIVE_WHITE_HAT, value: str = "example.com") -> Scope:
    return Scope(mode=mode, targets=(ScopeTarget(kind=TargetKind.WEBSITE, value=value),))


def test_scope_hash_stable_and_order_sensitive():
    a = make_scope()
    b = make_scope()
    assert a.sha256() == b.sha256()
    other = make_scope(value="other.com")
    assert a.sha256() != other.sha256()


def test_scope_requires_targets():
    with pytest.raises(ValidationError):
        Scope(mode=Mode.LOCAL_FILE, targets=())


def test_scope_rejects_whitespace_value():
    with pytest.raises(ValidationError):
        ScopeTarget(kind=TargetKind.WEBSITE, value="example .com")


def test_scope_contains():
    scope = make_scope()
    assert scope.contains(TargetKind.WEBSITE, "example.com")
    assert not scope.contains(TargetKind.WEBSITE, "evil.com")


def test_authorization_validity():
    auth = AuthorizationRecord(
        reference=" contract-1 ",
        scope_sha256=make_scope().sha256(),
        authorized_by="owner",
        valid_until=datetime.now(UTC) + timedelta(hours=1),
    )
    assert auth.is_valid_at()
    expired = auth.model_copy(update={"valid_until": datetime.now(UTC) - timedelta(hours=1)})
    assert not expired.is_valid_at()


def test_budgets_positive():
    with pytest.raises(ValidationError):
        ResourceBudget(max_steps=0)
    assert LIVE_BUDGET.max_requests < LAB_BUDGET.max_requests


def test_paths_xdg_override():
    env = {"XDG_CONFIG_HOME": "/xdg-test/cfg", "XDG_DATA_HOME": "/xdg-test/dat"}
    assert str(config_dir(env)).startswith("/xdg-test/cfg")
    assert str(data_dir(env)).startswith("/xdg-test/dat")
    assert database_path(env).name == "mauberesec.sqlite3"


def test_audit_event_details_redacted():
    from mauberesec.records import AuditEventRecord

    event = AuditEventRecord(
        category="test", decision="info", details="key sk-proj-AbCdEfGh1234567890IjKlMnOp"
    )
    assert "sk-proj-" not in event.details
    assert "[REDACTED" in event.details

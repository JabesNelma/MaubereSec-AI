"""Security tests: lab registration gates policy classification.

Only labs persisted in LabStore may classify targets as LOCAL_LAB.
Unregistering a lab must immediately revoke that status.
"""

import pytest

from mauberesec.docker.labs import LabProfile, LabService
from mauberesec.policy.gateway import LabRegistry, PolicyDenied, PolicyGateway, classify_target
from mauberesec.records import Mode, Scope, ScopeTarget, TargetKind
from mauberesec.storage.db import Database
from mauberesec.storage.lab_store import LabStore
from mauberesec.tools.registry import default_registry

PROFILE = LabProfile(
    name="sec-test-lab",
    subnet_cidr="10.66.99.0/24",
    services=(LabService(name="web", image="nginx:1.27-alpine"),),
)


@pytest.fixture()
def store(tmp_path):
    db = Database(tmp_path / "labs.sqlite3")
    yield LabStore(db)
    db.close()


def test_unregistered_subnet_fails_closed():
    empty = LabRegistry()
    assert classify_target("10.66.99.5", empty) == Mode.LIVE_WHITE_HAT


def test_registered_lab_grants_lab_mode(store):
    store.register(PROFILE)
    registry = store.policy_registry()
    assert classify_target("10.66.99.5", registry) == Mode.LOCAL_LAB
    # Outside the subnet still fails closed.
    assert classify_target("10.66.98.5", registry) == Mode.LIVE_WHITE_HAT


def test_unregister_revokes_lab_mode(store):
    store.register(PROFILE)
    assert classify_target("10.66.99.5", store.policy_registry()) == Mode.LOCAL_LAB
    store.unregister(PROFILE.name)
    assert classify_target("10.66.99.5", store.policy_registry()) == Mode.LIVE_WHITE_HAT


def test_lab_assessment_blocked_when_registration_removed(store, tmp_path):
    db = Database(tmp_path / "pol.sqlite3")
    store.register(PROFILE)
    gateway = PolicyGateway(db, default_registry(), store.policy_registry())
    scope = Scope(
        mode=Mode.LOCAL_LAB,
        targets=(ScopeTarget(kind=TargetKind.WEBSITE, value="10.66.99.5:80"),),
    )
    record = gateway.authorize_assessment(scope, None)
    assert record.mode == Mode.LOCAL_LAB

    # Teardown must revoke lab privileges immediately.
    store.unregister(PROFILE.name)
    gateway2 = PolicyGateway(db, default_registry(), store.policy_registry())
    with pytest.raises(PolicyDenied, match="not a registered local lab"):
        gateway2.authorize_assessment(scope, None)
    db.close()


def test_lab_store_roundtrip(store):
    store.register(PROFILE)
    regs = store.list()
    assert [r.profile.name for r in regs] == [PROFILE.name]
    fetched = store.get("sec-test-lab")
    assert fetched is not None
    assert fetched.profile.subnet_cidr == "10.66.99.0/24"
    store.unregister("sec-test-lab")
    assert store.get("sec-test-lab") is None

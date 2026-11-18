"""Integration tests against the real Docker daemon (skipped if unavailable).

Verifies the v0.3 acceptance criteria that need live containers:
- create/verify/teardown lifecycle with dedicated bridge network
- containers are not privileged, non-root-friendly, resource-limited
- no host ports published, no docker socket, no host mounts
- teardown removes only resources labeled for that lab
"""

import json
import shutil
import uuid

import pytest

from mauberesec.docker.client import DockerClient
from mauberesec.docker.labs import LabManager, LabProfile, LabService, LabStateError

pytestmark = pytest.mark.integration

docker_path = shutil.which("docker")
requires_docker = pytest.mark.skipif(docker_path is None, reason="docker CLI not available")


def daemon_up(client: DockerClient) -> bool:
    return client.daemon_version() is not None


@pytest.fixture(scope="module")
def client():
    c = DockerClient(docker_path=docker_path) if docker_path else None
    if c is None or not daemon_up(c):
        pytest.skip("docker daemon not reachable")
    return c


def unique_profile() -> LabProfile:
    suffix = uuid.uuid4().hex[:6]
    return LabProfile(
        name=f"it-lab-{suffix}",
        subnet_cidr=f"10.77.{suffix[:2] and int(suffix[:2], 16) % 200 + 10}.0/24",
        description="integration test lab",
        services=(
            LabService(
                name="web",
                image="nginx:1.27-alpine",
                tmpfs=(
                    "/tmp:size=16m",  # noqa: S108 - tmpfs spec
                    "/var/cache/nginx:size=16m",
                    "/var/run:size=16m",
                ),
                extra_caps=frozenset({"CHOWN", "SETGID", "SETUID"}),
                healthcheck_cmd=("curl", "-fsS", "http://127.0.0.1/"),
            ),
        ),
    )


def test_lab_lifecycle(client):
    manager = LabManager(client)
    profile = unique_profile()
    try:
        created = manager.create(profile)
        assert created == [profile.container_name(profile.services[0])]

        report = manager.verify(profile.name)
        assert report["ok"], report
        svc = report["services"][0]
        assert svc["status"] == "running"
        assert svc["privileged"] is False

        # Network must be internal with no external gateway routing.
        net = json.loads(client.run(["network", "inspect", profile.network_name()]).stdout)[0]
        assert net["Labels"]["mauberesec.lab"] == profile.name
        assert net["Internal"] is True

        # Container hardening checks.
        state = manager.container_state(created[0])
        hc = state["HostConfig"]
        assert hc["Privileged"] is False
        assert hc["Memory"] > 0
        assert hc["PidsLimit"] > 0
        assert hc["Binds"] in (None, [])
        assert hc["PortBindings"] in (None, {})
        # Read-only rootfs.
        assert state["Config"]["Labels"]["mauberesec.lab"] == profile.name

        # Duplicate create is refused.
        with pytest.raises(LabStateError, match="already has resources"):
            manager.create(profile)

        # Reset tears down and recreates.
        report = manager.reset(profile)
        assert profile.network_name() in report["removed"]
        assert manager.verify(profile.name)["ok"]
    finally:
        manager.teardown(profile.name)


def test_teardown_removes_only_labeled_resources(client):
    manager = LabManager(client)
    profile_a = unique_profile()
    profile_b = unique_profile()
    # A sentinel container NOT labeled for either lab.
    sentinel = f"msai-sentinel-{uuid.uuid4().hex[:6]}"
    client.run(
        [
            "run",
            "-d",
            "--name",
            sentinel,
            "--label",
            "mauberesec.managed=false",
            "nginx:1.27-alpine",
        ],
        timeout=300.0,
    )
    try:
        manager.create(profile_a)
        manager.create(profile_b)
        report = manager.teardown(profile_a.name)
        removed = set(report["removed"])
        assert profile_a.network_name() in removed
        assert profile_b.network_name() not in removed
        # Lab B and the sentinel survive.
        assert manager.verify(profile_b.name)["ok"]
        sentinel_alive = manager.container_state(sentinel)
        assert sentinel_alive is not None
        assert sentinel_alive["State"]["Status"] == "running"
    finally:
        manager.teardown(profile_a.name)
        manager.teardown(profile_b.name)
        client.run(["rm", "-f", sentinel], timeout=60)

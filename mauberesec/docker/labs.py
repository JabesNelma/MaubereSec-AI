"""Local lab manager: isolated, disposable training targets.

Every lab gets a dedicated bridge network with a fixed subnet, containers
with resource limits, non-root-friendly hardening (cap_drop ALL,
no-new-privileges, read-only rootfs), health checks, and no host port
publishing. All created resources carry labels so teardown touches only
what this lab created.
"""

from __future__ import annotations

import json
import shlex
from ipaddress import ip_network
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .client import DockerClient

LAB_LABEL = "mauberesec.lab"
MANAGED_LABEL = "mauberesec.managed"

DEFAULT_MEMORY = "128m"
DEFAULT_CPUS = "0.25"
DEFAULT_PIDS = 64

# Only these capabilities may ever be added back after cap_drop ALL.
ALLOWED_EXTRA_CAPS = frozenset(
    {"CHOWN", "SETUID", "SETGID", "NET_BIND_SERVICE", "DAC_OVERRIDE", "KILL"}
)


class LabService(BaseModel):
    """One container inside a lab."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    image: str = Field(min_length=1)
    environment: tuple[str, ...] = ()
    mem_limit: str = DEFAULT_MEMORY
    cpus: str = DEFAULT_CPUS
    pids_limit: int = Field(default=DEFAULT_PIDS, ge=1)
    healthcheck_cmd: tuple[str, ...] = ()
    healthcheck_interval: int = Field(default=5, ge=1)
    tmpfs: tuple[str, ...] = ("/tmp:size=16m,mode=1777",)  # noqa: S108 - tmpfs spec
    read_only: bool = True
    extra_caps: frozenset[str] = frozenset()

    @field_validator("extra_caps")
    @classmethod
    def _caps_allowlisted(cls, v: frozenset[str]) -> frozenset[str]:
        illegal = set(v) - ALLOWED_EXTRA_CAPS
        if illegal:
            raise ValueError(f"Capabilities {sorted(illegal)} are not in the lab allowlist.")
        return v


class LabProfile(BaseModel):
    """A registered lab template: dedicated network + services."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    subnet_cidr: str
    description: str = ""
    services: tuple[LabService, ...] = Field(min_length=1)

    @field_validator("subnet_cidr")
    @classmethod
    def _valid_cidr(cls, v: str) -> str:
        try:
            net = ip_network(v, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR '{v}'.") from exc
        if not net.is_private:
            raise ValueError("Lab subnet must be a private range (RFC1918).")
        if net.prefixlen < 24:
            raise ValueError("Lab subnet must be /24 or smaller.")
        return v

    def network_name(self) -> str:
        return f"msai-lab-{self.name}-net"

    def container_name(self, service: LabService) -> str:
        return f"msai-lab-{self.name}-{service.name}"


class LabStateError(Exception):
    """Lab operation failed or lab state is inconsistent."""


class LabManager:
    """Create, verify, reset, and tear down labeled lab environments."""

    def __init__(self, client: DockerClient) -> None:
        self._docker = client

    # -- helpers -----------------------------------------------------------------

    def _run(self, args: list[str], timeout: float = 120.0) -> str:
        result = self._docker.run(args, timeout=timeout)
        if not result.ok:
            raise LabStateError(f"docker {' '.join(args[:3])} failed: {result.stderr.strip()}")
        return result.stdout

    def _labels(self, profile: LabProfile) -> list[str]:
        return [f"{MANAGED_LABEL}=true", f"{LAB_LABEL}={profile.name}"]

    def _find_lab_resources(self, lab_name: str) -> tuple[list[str], str | None]:
        """Return (container names, network name) labeled for *lab_name*."""
        out = self._run(
            [
                "container",
                "ls",
                "-a",
                "--format",
                "{{.Names}}",
                "--filter",
                f"label={LAB_LABEL}={lab_name}",
            ]
        )
        containers = [line for line in out.splitlines() if line.strip()]
        net = f"msai-lab-{lab_name}-net"
        probe = self._docker.run(["network", "inspect", net], timeout=15)
        return containers, net if probe.ok else None

    # -- lifecycle -----------------------------------------------------------------

    def create(self, profile: LabProfile) -> list[str]:
        """Create the dedicated network and all service containers."""
        # Fail fast if anything from a previous run survives.
        containers, network = self._find_lab_resources(profile.name)
        if containers or network:
            raise LabStateError(
                f"Lab '{profile.name}' already has resources; run reset or teardown first."
            )

        self._run(
            [
                "network",
                "create",
                "--driver",
                "bridge",
                "--subnet",
                profile.subnet_cidr,
                "--label",
                f"{LAB_LABEL}={profile.name}",
                "--label",
                f"{MANAGED_LABEL}=true",
                "--internal",
                profile.network_name(),
            ]
        )

        created: list[str] = []
        try:
            for service in profile.services:
                args = [
                    "run",
                    "-d",
                    "--name",
                    profile.container_name(service),
                    "--network",
                    profile.network_name(),
                    "--memory",
                    service.mem_limit,
                    "--cpus",
                    service.cpus,
                    "--pids-limit",
                    str(service.pids_limit),
                    "--cap-drop",
                    "ALL",
                    *(
                        cap_arg
                        for cap in sorted(service.extra_caps)
                        for cap_arg in ("--cap-add", cap)
                    ),
                    "--security-opt",
                    "no-new-privileges",
                    *(["--read-only"] if service.read_only else []),
                ]
                for label in self._labels(profile):
                    args += ["--label", label]
                for tmpfs in service.tmpfs:
                    args += ["--tmpfs", tmpfs]
                for env in service.environment:
                    args += ["-e", env]
                if service.healthcheck_cmd:
                    args += [
                        "--health-cmd",
                        " ".join(shlex.quote(c) for c in service.healthcheck_cmd),
                        "--health-interval",
                        f"{service.healthcheck_interval}s",
                        "--health-retries",
                        "3",
                    ]
                args.append(service.image)
                self._run(["pull", service.image], timeout=600.0)
                self._run(args, timeout=300.0)
                created.append(profile.container_name(service))
        except LabStateError:
            # Roll back partial creation.
            self.teardown(profile.name)
            raise
        return created

    def verify(self, lab_name: str) -> dict[str, Any]:
        """Verify network existence, labels, container state, and health."""
        containers, network = self._find_lab_resources(lab_name)
        if network is None:
            return {"ok": False, "reason": f"No network found for lab '{lab_name}'."}

        inspect = self._docker.run(["network", "inspect", network], timeout=15)
        info = json.loads(inspect.stdout)[0] if inspect.ok else {}
        labels = info.get("Labels") or {}
        if labels.get(LAB_LABEL) != lab_name:
            return {"ok": False, "reason": "Network is not labeled for this lab."}

        services: list[dict[str, Any]] = []
        for name in containers:
            state = self.container_state(name)
            if state is None:
                services.append({"container": name, "status": "missing"})
                continue
            services.append(
                {
                    "container": name,
                    "status": state.get("State", {}).get("Status", "unknown"),
                    "health": state.get("State", {}).get("Health", {}).get("Status", "n/a"),
                    "privileged": self._is_privileged(state),
                }
            )
        ok = bool(containers) and all(
            s["status"] == "running" and not s["privileged"] for s in services
        )
        return {"ok": ok, "network": network, "services": services}

    def service_containers(self, lab_name: str) -> list[str]:
        """Public: container names labeled for *lab_name*."""
        containers, _network = self._find_lab_resources(lab_name)
        return containers

    def container_state(self, name: str) -> dict[str, Any] | None:
        result = self._docker.run(["container", "inspect", name], timeout=15)
        if not result.ok:
            return None
        state: dict[str, Any] = json.loads(result.stdout)[0]
        return state

    @staticmethod
    def _is_privileged(state: dict[str, Any]) -> bool:
        return bool(state.get("HostConfig", {}).get("Privileged"))

    def teardown(self, lab_name: str) -> dict[str, Any]:
        """Remove only resources labeled for *lab_name*."""
        containers, network = self._find_lab_resources(lab_name)
        removed: list[str] = []
        for name in containers:
            self._docker.run(["rm", "-f", name], timeout=60)
            removed.append(name)
        if network:
            self._docker.run(["network", "rm", network], timeout=60)
            removed.append(network)
        return {"removed": removed}

    def reset(self, profile: LabProfile) -> dict[str, Any]:
        """Teardown followed by a fresh create."""
        report = self.teardown(profile.name)
        self.create(profile)
        return report


# --- Built-in profiles -----------------------------------------------------------


def builtin_profiles() -> dict[str, LabProfile]:
    """Seeded training-lab templates (pinned images)."""
    demo = LabProfile(
        name="demo-web",
        subnet_cidr="10.66.7.0/24",
        description="Minimal demo lab: a static web target for passive checks.",
        services=(
            LabService(
                name="web",
                image="nginx:1.27-alpine",
                tmpfs=(
                    "/tmp:size=16m,mode=1777",  # noqa: S108 - tmpfs spec
                    "/var/cache/nginx:size=16m",
                    "/var/run:size=16m",
                ),
                extra_caps=frozenset({"CHOWN", "SETGID", "SETUID"}),
                healthcheck_cmd=("curl", "-fsS", "http://127.0.0.1/"),
            ),
        ),
    )
    return {demo.name: demo}

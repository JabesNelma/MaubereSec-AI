"""Fixed, narrowly scoped wrapper around the Docker CLI.

Security rules (TECHNICAL_ARCHITECTURE §6, SECURITY_POLICY §4):
- Only allowlisted subcommands may be executed.
- ``--privileged`` is forbidden.
- Mounting the Docker socket, any ``/var/run/docker.sock``-style path,
  or any host path via ``-v``/``--mount`` into containers is forbidden.
- ``--network host`` and ``--pid=host`` are forbidden.
- Arguments come from fixed lab profiles, never from model output.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

FORBIDDEN_TOKENS = (
    "--privileged",
    "/var/run/docker.sock",
    "--network=host",
    "--net=host",
    "--pid=host",
)

ALLOWED_PREFIXES: tuple[tuple[str, ...], ...] = (
    ("version",),
    ("network", "create"),
    ("network", "inspect"),
    ("network", "ls"),
    ("network", "rm"),
    ("container", "inspect"),
    ("container", "ls"),
    ("rm",),
    ("stop",),
    ("run",),
    ("pull",),
)


class DockerCommandError(Exception):
    """A docker CLI invocation failed or was rejected by policy."""


@dataclass(frozen=True)
class DockerResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def _validate_args(args: list[str], *, allow_ro_host_mounts: bool = False) -> None:
    if not args:
        raise DockerCommandError("Empty docker command.")
    joined = " ".join(args)
    for token in FORBIDDEN_TOKENS:
        if token in joined:
            raise DockerCommandError(f"Docker argument '{token}' is forbidden by policy.")
    # Space-separated forms: "--network host", "--net host", "--pid host".
    for flag in ("--network", "--net", "--pid"):
        for i, arg in enumerate(args[:-1]):
            if arg == flag and args[i + 1] == "host":
                raise DockerCommandError(f"Docker argument '{flag} host' is forbidden by policy.")
    # Host filesystem mounts into containers are forbidden; named Docker
    # volumes are allowed. The only exception is pre-validated read-only
    # scanner mounts ending in ":ro", and those are only ever constructed
    # by DockerClient.run_scanner (allow_ro_host_mounts=True).
    prev = ""
    for arg in args:
        if prev in ("-v", "--volume", "--mount"):
            host_side = arg.split(":")[0]
            is_ro_scanner_mount = (
                allow_ro_host_mounts and arg.endswith(":ro") and arg.count(":") >= 2
            )
            if (
                arg.startswith(("/", ".", "~")) or host_side.startswith("/")
            ) and not is_ro_scanner_mount:
                raise DockerCommandError(f"Host path mount '{arg}' is forbidden by policy.")
        prev = arg
    for prefix in ALLOWED_PREFIXES:
        if tuple(args[: len(prefix)]) == prefix:
            return
    raise DockerCommandError(f"Docker subcommand '{joined.split()[0]}…' is not in the allowlist.")


class DockerClient:
    """Runs allowlisted docker CLI commands via subprocess."""

    def __init__(self, docker_path: str | None = None, timeout: float = 60.0) -> None:
        # docker_path=None -> auto-detect; empty string -> explicitly disabled.
        self._docker = docker_path if docker_path is not None else shutil.which("docker")
        self._timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self._docker)

    def run(self, args: list[str], timeout: float | None = None) -> DockerResult:
        return self._run_validated(args, timeout, allow_ro_host_mounts=False)

    def _run_validated(
        self,
        args: list[str],
        timeout: float | None,
        *,
        allow_ro_host_mounts: bool,
    ) -> DockerResult:
        if not self.available or self._docker is None:
            raise DockerCommandError("docker CLI not found on PATH.")
        _validate_args(args, allow_ro_host_mounts=allow_ro_host_mounts)

        proc = subprocess.run(  # noqa: S603 - allowlisted args only
            [self._docker, *args],
            capture_output=True,
            text=True,
            timeout=timeout or self._timeout,
        )
        return DockerResult(proc.returncode, proc.stdout, proc.stderr)

    def daemon_version(self) -> str | None:
        result = self.run(["version", "--format", "{{.Server.Version}}"], timeout=15)
        return result.stdout.strip() if result.ok else None

    def run_scanner(
        self,
        image: str,
        command: list[str],
        *,
        host_path: str,
        container_path: str = "/src",
        timeout: float = 600.0,
        allow_network: bool = False,
        entrypoint: str | None = None,
        env: dict[str, str] | None = None,
        extra_ro_mounts: list[tuple[str, str]] | None = None,
        network_name: str | None = None,
    ) -> DockerResult:
        """Run a scanner container over a read-only source mount.

        Hardening: --rm, network disabled, all capabilities dropped,
        no-new-privileges, read-only rootfs, and the source mounted
        strictly read-only. The command comes from fixed adapter code —
        never from model output or repository content.

        Network is disabled by default. ``allow_network=True`` grants the
        default bridge network for scanners that must download rules or
        advisories (semgrep, OSV); they still cannot reach the local
        target, which is a mounted directory, and never the host network.
        ``network_name`` attaches the container to exactly one named
        Docker network (used for lab-internal probes); it takes
        precedence over ``allow_network``.

        ``label=disable`` turns off SELinux confinement for this container
        only: on SELinux hosts (e.g. Fedora rootless Docker) container
        processes otherwise cannot read user-labeled files. The user's
        files are never relabeled (no ``:z``); isolation remains enforced
        by the read-only mount, dropped capabilities, no network, and the
        read-only rootfs.
        """
        if not os.path.isabs(host_path):
            raise DockerCommandError("Scanner host path must be absolute.")
        mounts = [(host_path, container_path)]
        for extra_host, extra_container in extra_ro_mounts or []:
            if not os.path.isabs(extra_host) or not extra_container.startswith("/"):
                raise DockerCommandError("Extra scanner mounts must be absolute.")
            mounts.append((extra_host, extra_container))
        if network_name is not None:
            if not network_name.replace("-", "").replace("_", "").isalnum():
                raise DockerCommandError("Invalid Docker network name.")
            network_args: list[str] = ["--network", network_name]
        else:
            network_args = ["--network", "none"] if not allow_network else []
        args = [
            "run",
            "--rm",
            *network_args,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--security-opt",
            "label=disable",
            "--read-only",
            "--tmpfs",
            "/tmp:size=64m,mode=1777",  # noqa: S108 - tmpfs spec
            *(["--entrypoint", entrypoint] if entrypoint else []),
            *(arg for key, value in (env or {}).items() for arg in ("-e", f"{key}={value}")),
            *(arg for h, c in mounts for arg in ("-v", f"{h}:{c}:ro")),
            image,
            *command,
        ]
        return self._run_validated(args, timeout, allow_ro_host_mounts=True)

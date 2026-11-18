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


def _validate_args(args: list[str]) -> None:
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
    # volumes are allowed.
    prev = ""
    for arg in args:
        if prev in ("-v", "--volume", "--mount"):
            host_side = arg.split(":")[0]
            if arg.startswith(("/", ".", "~")) or host_side.startswith("/"):
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
        if not self.available or self._docker is None:
            raise DockerCommandError("docker CLI not found on PATH.")
        _validate_args(args)
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

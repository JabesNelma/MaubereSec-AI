"""Disposable Android emulator orchestration (v0.9, experimental).

Isolation model:
- A dedicated **internal** Docker network per run (`--internal`): the
  emulator container has no route off that boundary — network egress stays
  within the registered emulator/lab boundary.
- The emulator image boots the disposable Android emulator inside the
  container; every ``adb`` call runs **inside** that container via
  ``docker exec`` against its own emulator endpoint. The host's adb is never
  used, so no personal device can ever be targeted.
- Synthetic dataset only (mauberesec.android.fixtures).
- Reset between runs is *verified*: each run starts a brand-new container
  from the same immutable image and the runner asserts the container
  identity differs from the previous run's. Image-level snapshots
  (``docker commit``) are deliberately not used, keeping the Docker
  allowlist minimal.

Unsupported hosts are refused up front (hostcheck) so isolation is never
silently degraded.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..docker.client import DockerClient, DockerCommandError
from .fixtures import dataset_marker, write_synthetic_dataset
from .hostcheck import HostCapability, require_emulator_support

DEFAULT_EMULATOR_IMAGE = "budtmo/docker-android:emulator_11.0"
ENTRY_SCRIPT = "/analyzer/emulator_entry.sh"


class EmulatorRunError(Exception):
    """The dynamic run could not complete safely."""


@dataclass(frozen=True)
class EmulatorSpec:
    apk_path: Path
    package: str
    image: str = DEFAULT_EMULATOR_IMAGE
    logcat_seconds: int = 20
    boot_timeout: float = 600.0


@dataclass
class EmulatorRunReport:
    run_id: str
    network: str
    container_id: str
    emulator: dict[str, Any] = field(default_factory=dict)
    reset_verified: bool = False
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"run {self.run_id}: network={self.network} "
            f"container={self.container_id[:12] or 'unknown'} "
            f"reset_verified={self.reset_verified} "
            f"installed={self.emulator.get('apk_installed')} "
            f"launched={self.emulator.get('launched')}"
        )


class EmulatorRunner:
    """Runs one disposable emulator session under a synthetic profile."""

    def __init__(self, client: DockerClient) -> None:
        self._client = client
        self._entry_dir = Path(__file__).resolve().parent / "container"

    # -- lifecycle helpers -------------------------------------------------------

    @staticmethod
    def _network_name(run_id: str) -> str:
        return f"msai-emu-{run_id}-net"

    @staticmethod
    def _container_name(run_id: str) -> str:
        return f"msai-emu-{run_id}-emu"

    def create_isolated_network(self, run_id: str) -> str:
        """Internal bridge network: nothing leaves this boundary."""
        name = self._network_name(run_id)
        result = self._client.run(
            [
                "network",
                "create",
                "--driver",
                "bridge",
                "--internal",
                "--label",
                "mauberesec.managed=true",
                "--label",
                f"mauberesec.emulator={run_id}",
                name,
            ]
        )
        if not result.ok:
            raise EmulatorRunError(f"network create failed: {result.stderr[:200]}")
        return name

    def teardown(self, run_id: str) -> list[str]:
        removed: list[str] = []
        container = self._container_name(run_id)
        probe = self._client.run(["container", "inspect", container], timeout=15)
        if probe.ok:
            self._client.remove_container(container)
            removed.append(container)
        network = self._network_name(run_id)
        net_probe = self._client.run(["network", "inspect", network], timeout=15)
        if net_probe.ok:
            self._client.run(["network", "rm", network], timeout=60)
            removed.append(network)
        return removed

    # -- run --------------------------------------------------------------------

    def run(
        self,
        spec: EmulatorSpec,
        capability: HostCapability,
        previous_container_id: str | None = None,
    ) -> EmulatorRunReport:
        require_emulator_support(capability)
        if not spec.apk_path.is_file():
            raise EmulatorRunError(f"APK not found: {spec.apk_path}")
        if not self._client.available:
            raise EmulatorRunError("docker CLI not available.")

        run_id = uuid.uuid4().hex[:10]
        workdir = Path(tempfile.mkdtemp(prefix=f"msai-emu-{run_id}-"))
        report = EmulatorRunReport(run_id=run_id, network="", container_id="")
        container_name = self._container_name(run_id)

        try:
            write_synthetic_dataset(workdir / "dataset")
            report.network = self.create_isolated_network(run_id)

            if not self._client.image_exists(spec.image):
                pull = self._client.run(["pull", spec.image], timeout=3600.0)
                if not pull.ok:
                    raise EmulatorRunError(
                        f"cannot pull emulator image '{spec.image}': {pull.stderr[:200]}"
                    )

            container_id = self._client.run_emulator_container(
                spec.image,
                name=container_name,
                network=report.network,
                read_only_mounts=[
                    (str(spec.apk_path.parent), "/apk"),
                    (str(self._entry_dir), "/analyzer"),
                    (str(workdir / "dataset"), "/dataset"),
                ],
                env={"MSAI_RUN_ID": run_id},
                timeout=spec.boot_timeout,
            )
            report.container_id = container_id
            report.notes.append("adb runs inside the container only; host adb is never used")

            result = self._client.exec_in(
                container_name,
                [
                    "sh",
                    ENTRY_SCRIPT,
                    f"/apk/{spec.apk_path.name}",
                    spec.package,
                    "/dataset",
                    str(spec.logcat_seconds),
                    run_id,
                ],
                timeout=spec.boot_timeout + 300,
            )
            parsed = _parse_last_json(result.stdout)
            if parsed is None or "error" in parsed:
                detail = (parsed or {}).get("error") or result.stderr[:300] or "no JSON output"
                report.notes.append(str(detail))
                raise EmulatorRunError(f"emulator run failed: {detail}")
            report.emulator = parsed

            # Reset verification: fresh container per run, distinct identity.
            verified = bool(report.container_id)
            if previous_container_id:
                verified = verified and report.container_id != previous_container_id
                if not verified:
                    report.notes.append("reset NOT verified: container identity reused")
            report.reset_verified = verified

            if dataset_marker() in str(parsed.get("logcat_tail", "")):
                report.notes.append("synthetic dataset marker observed in logcat")
            return report
        except DockerCommandError as exc:
            raise EmulatorRunError(f"docker failed: {exc}") from exc
        finally:
            self.teardown(run_id)
            shutil.rmtree(workdir, ignore_errors=True)


def _parse_last_json(text: str) -> dict[str, Any] | None:
    for line in reversed([ln for ln in text.splitlines() if ln.strip()]):
        if not line.strip().startswith("{"):
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None

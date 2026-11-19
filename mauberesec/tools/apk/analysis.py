"""Host-side APK analysis adapter: runs the container analyzer, maps findings."""

from __future__ import annotations

import json
import os
import shutil
import uuid
from pathlib import Path

from ...docker.client import DockerClient, DockerCommandError
from ...paths import data_dir
from ...records import Confidence, FindingRecord, Severity
from ..source_audit.adapters import ScannerUnavailable

ANALYZER_IMAGE = "python:3.12-alpine"


def _stage_apk(apk_path: Path) -> Path:
    """Copy the APK into a controlled, world-traversable input location.

    Mirrors TECHNICAL_ARCHITECTURE §9 step 3 and sidesteps unreadable
    parent directories inside the container (no capabilities are granted).
    """
    stage = data_dir() / "apk-staging" / uuid.uuid4().hex
    stage.mkdir(parents=True)
    for part in [stage, *stage.parents]:
        if part == data_dir().parent or part == Path.home():
            break
        try:
            os.chmod(part, 0o755)  # noqa: S103 - staging dir traversal only
        except OSError:
            break
    dest = stage / apk_path.name
    shutil.copy2(apk_path, dest)
    os.chmod(dest, 0o644)
    return dest


class ApkAnalyzerAdapter:
    """Runs tools/apk/container/apk_analyzer.py inside a restricted container."""

    name = "apk.static_review"
    image = ANALYZER_IMAGE

    def __init__(self, client: DockerClient) -> None:
        self._client = client
        self._analyzer_dir = Path(__file__).resolve().parent / "container"

    def run(self, apk_host_path: str, sha256: str) -> tuple[dict[str, object], list[FindingRecord]]:
        if not self._client.available:
            raise ScannerUnavailable("docker CLI not available.")
        apk_path = Path(apk_host_path)
        staged = _stage_apk(apk_path)
        script_dir = str(self._analyzer_dir)
        try:
            pull = self._client.run(["pull", ANALYZER_IMAGE], timeout=900.0)
            if not pull.ok:
                raise ScannerUnavailable(f"cannot pull {ANALYZER_IMAGE}: {pull.stderr[:200]}")
            result = self._client.run_scanner(
                ANALYZER_IMAGE,
                ["python3", "/analyzer/apk_analyzer.py", f"/src/{staged.name}", sha256],
                host_path=str(staged.parent),
                container_path="/src",
                extra_ro_mounts=[(script_dir, "/analyzer")],
                timeout=600.0,
            )
        except DockerCommandError as exc:
            raise ScannerUnavailable(f"docker failed: {exc}") from exc
        finally:
            shutil.rmtree(staged.parent, ignore_errors=True)

        if not result.stdout.strip():
            raise ScannerUnavailable(
                f"apk analyzer exited {result.returncode}: {result.stderr[:300]}"
            )
        try:
            report = json.loads(result.stdout.strip().splitlines()[-1])
            if not isinstance(report, dict):
                raise ScannerUnavailable("analyzer output is not a JSON object")
        except json.JSONDecodeError as exc:
            raise ScannerUnavailable(f"unparseable analyzer output: {exc}") from exc
        if "error" in report:
            raise ScannerUnavailable(f"apk analyzer failed: {report['error']}")
        findings_raw = report.get("findings", [])
        if not isinstance(findings_raw, list):
            raise ScannerUnavailable("analyzer findings are not a list")

        severity_map = {
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        confidence_map = {
            "high": Confidence.HIGH,
            "medium": Confidence.MEDIUM,
            "low": Confidence.LOW,
        }
        findings = []
        for item in report.get("findings", []):
            findings.append(
                FindingRecord(
                    title=str(item.get("title", "APK finding"))[:200],
                    severity=severity_map.get(str(item.get("severity")), Severity.LOW),
                    confidence=confidence_map.get(str(item.get("confidence")), Confidence.MEDIUM),
                    tool_name=self.name,
                    evidence=str(item.get("evidence", ""))[:1000],
                    remediation=str(item.get("remediation", ""))[:500],
                )
            )
        return report, findings

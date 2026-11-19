"""Scanner adapters for local source-code audit (v0.5).

Each adapter runs a pinned scanner image through DockerClient.run_scanner
(read-only mount, no network, cap_drop ALL) with a **fixed** command, then
parses its JSON from stdout into FindingRecords. Project code is never
executed and project dependencies are never installed.

Secret handling: raw secret values from secret scanners are never copied
into findings or evidence — only file/line/rule metadata is kept.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from ...docker.client import DockerClient, DockerCommandError
from ...records import Confidence, FindingRecord, Severity
from ...redaction import redact

SEMGREP_IMAGE = "semgrep/semgrep:1.86.0"
GITLEAKS_IMAGE = "zricethezav/gitleaks:v8.24.3"
OSV_SCANNER_IMAGE = "ghcr.io/google/osv-scanner:v1.9.2"


class ScannerUnavailable(Exception):
    """Docker or the scanner image is unavailable."""


class ScannerAdapter(Protocol):
    name: str
    image: str

    def run(self, host_path: str) -> list[FindingRecord]: ...


@dataclass(frozen=True)
class AdapterSpec:
    name: str
    image: str
    command: tuple[str, ...]
    allow_network: bool = False  # outbound for rules/advisories only
    entrypoint: str | None = None  # fixed image entrypoint override
    env: dict[str, str] | None = None  # fixed environment (e.g. writable HOME)


SEMGREP_SPEC = AdapterSpec(
    name="static.semgrep",
    image=SEMGREP_IMAGE,
    command=("semgrep", "--config", "auto", "--json", "--quiet", "/src"),
    allow_network=True,  # downloads rule packs from the semgrep registry
    env={"HOME": "/tmp"},  # noqa: S108 - writable home inside the container
)
GITLEAKS_SPEC = AdapterSpec(
    name="static.gitleaks",
    image=GITLEAKS_IMAGE,
    entrypoint="sh",
    command=(
        # Fixed script: scan to a tmpfs report file, then print it.
        # (Direct /dev/stdout capture is unreliable for this image.)
        "-c",
        "gitleaks detect --source /src --report-format json "
        "--report-path /tmp/gitleaks.json --no-banner --exit-code 0 --redact; "
        "cat /tmp/gitleaks.json",
    ),
)
OSV_SPEC = AdapterSpec(
    name="static.osv_scanner",
    image=OSV_SCANNER_IMAGE,
    command=("--json", "--recursive", "/src"),
    allow_network=True,  # queries api.osv.dev for advisories
)


class DockerScannerAdapter:
    """Runs one scanner image with a fixed command and parses JSON stdout."""

    def __init__(
        self,
        spec: AdapterSpec,
        client: DockerClient,
        parser: Callable[[str], list[FindingRecord]],
    ) -> None:
        self.name = spec.name
        self.image = spec.image
        self._spec = spec
        self._client = client
        self._parser = parser

    def run(self, host_path: str) -> list[FindingRecord]:
        if not self._client.available:
            raise ScannerUnavailable("docker CLI not available.")
        try:
            # Pull first so image-download noise never pollutes scanner stdout.
            pull = self._client.run(["pull", self._spec.image], timeout=900.0)
            if not pull.ok:
                raise ScannerUnavailable(f"cannot pull {self._spec.image}: {pull.stderr[:200]}")
            result = self._client.run_scanner(
                self._spec.image,
                list(self._spec.command),
                host_path=host_path,
                allow_network=self._spec.allow_network,
                entrypoint=self._spec.entrypoint,
                env=self._spec.env,
            )
        except DockerCommandError as exc:
            raise ScannerUnavailable(f"docker failed: {exc}") from exc
        if not result.stdout.strip() and not result.ok:
            raise ScannerUnavailable(
                f"{self.name} exited {result.returncode}: {result.stderr[:300]}"
            )
        return self._parser(result.stdout)


# --- parsers (pure functions; unit-testable) --------------------------------------


def _finding(
    tool: str,
    title: str,
    severity: Severity,
    file: str,
    line: int | None,
    evidence: str,
    remediation: str,
    confidence: Confidence = Confidence.MEDIUM,
) -> FindingRecord:
    location = f"{file}:{line}" if line is not None else file
    return FindingRecord(
        title=title,
        severity=severity,
        confidence=confidence,
        tool_name=tool,
        evidence=redact(f"[{location}] {evidence}")[:1000],
        remediation=remediation,
    )


def parse_semgrep(stdout: str) -> list[FindingRecord]:
    data = json.loads(stdout or "{}")
    findings: list[FindingRecord] = []
    for result in data.get("results", []):
        extra = result.get("extra", {})
        severity_map = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}
        findings.append(
            _finding(
                tool="static.semgrep",
                title=str(result.get("check_id", "semgrep-finding")),
                severity=severity_map.get(str(extra.get("severity", "")).upper(), Severity.LOW),
                file=str(result.get("path", "")),
                line=int(result.get("start", {}).get("line", 0)) or None,
                evidence=str(extra.get("message", "")),
                remediation=str(extra.get("fix", "") or "Review and fix the flagged pattern."),
            )
        )
    return findings


def parse_gitleaks(stdout: str) -> list[FindingRecord]:
    findings: list[FindingRecord] = []
    for item in json.loads(stdout or "[]"):
        # Secret value intentionally omitted — only metadata is kept.
        findings.append(
            _finding(
                tool="static.gitleaks",
                title=f"Possible secret: {item.get('RuleID', 'unknown-rule')}",
                severity=Severity.HIGH,
                file=str(item.get("File", "")),
                line=int(item.get("StartLine", 0)) or None,
                evidence=(
                    f"gitleaks rule {item.get('RuleID')} matched "
                    f"(fingerprint {item.get('Fingerprint', 'n/a')}); "
                    "secret value withheld."
                ),
                remediation="Remove the secret, rotate it, and use a secret manager.",
                confidence=Confidence.HIGH,
            )
        )
    return findings


def parse_osv(stdout: str) -> list[FindingRecord]:
    data = json.loads(stdout or "{}")
    findings: list[FindingRecord] = []
    for result in data.get("results", []):
        for pkg in result.get("packages", []):
            package = pkg.get("package", {})
            for advisory in pkg.get("advisories", []):
                findings.append(
                    _finding(
                        tool="static.osv_scanner",
                        title=f"Vulnerable dependency: {package.get('name', '?')} "
                        f"{package.get('version', '?')} — {advisory.get('id', '?')}",
                        severity=Severity.MEDIUM,
                        file=str(result.get("source", {}).get("path", "")),
                        line=None,
                        evidence=f"{advisory.get('id')}: {advisory.get('summary', '')}",
                        remediation="Upgrade the dependency to a fixed version.",
                        confidence=Confidence.HIGH,
                    )
                )
    return findings


# --- deduplication ------------------------------------------------------------------


def dedup_findings(findings: list[FindingRecord]) -> list[FindingRecord]:
    """Deterministic dedup by (tool, title, evidence location prefix)."""
    seen: set[str] = set()
    out: list[FindingRecord] = []
    for finding in findings:
        location = finding.evidence.split("]")[0] if finding.evidence.startswith("[") else ""
        key = f"{finding.tool_name}|{finding.title}|{location}"
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def default_adapters(client: DockerClient) -> list[DockerScannerAdapter]:
    return [
        DockerScannerAdapter(SEMGREP_SPEC, client, parse_semgrep),
        DockerScannerAdapter(GITLEAKS_SPEC, client, parse_gitleaks),
        DockerScannerAdapter(OSV_SPEC, client, parse_osv),
    ]

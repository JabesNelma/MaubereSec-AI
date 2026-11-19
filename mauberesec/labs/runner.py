"""Lab validation runner (v0.8): bounded, confirmed, resettable lab tests.

Rules enforced here:
- The lab must be registered (LabStore) and its containers verified healthy.
- Safe checks always run against the verified lab; state-changing checks
  run only with explicit per-run confirmation, and each one is policy
  checked (lab.controlled_validation requires confirm_state_change).
- Every check and every decision is audited.
- After the run the lab health is re-verified; with reset_after=True the
  lab is reset to its baseline (roadmap: reset restores expected baseline).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..docker.client import DockerClient, DockerCommandError
from ..docker.labs import LabManager
from ..records import AuditEventRecord, FindingRecord, Severity, ToolRunRecord
from ..storage.db import Database
from ..storage.lab_store import LabStore
from .container import lab_probe
from .profiles import LabTestProfile, build_probe_payload

PROBE_IMAGE = "python:3.12-alpine"


class LabTestError(Exception):
    """Lab validation could not proceed."""


def discover_service_base_url(manager: LabManager, lab_name: str, port: int = 80) -> str:
    """Find the first healthy service container's IP on the lab network."""
    containers = manager.service_containers(lab_name)
    for name in containers:
        state = manager.container_state(name)
        if not state:
            continue
        networks = (state.get("NetworkSettings") or {}).get("Networks") or {}
        for net in networks.values():
            ip = net.get("IPAddress")
            if ip:
                return f"http://{ip}:{port}"
    raise LabTestError(f"No service container with an IP found for lab '{lab_name}'.")


class LabValidationRunner:
    def __init__(
        self,
        db: Database,
        client: DockerClient,
        assessment_id: str,
        on_audit: Any = None,
    ) -> None:
        self._db = db
        self._client = client
        self._assessment_id = assessment_id
        self._manager = LabManager(client)
        self._store = LabStore(db)
        self._audit_hook = on_audit

    def _audit(self, decision: str, details: str, category: str = "lab_test") -> None:
        self._db.save_audit_event(
            AuditEventRecord(
                assessment_id=self._assessment_id,
                category=category,
                decision=decision,
                details=details,
            )
        )
        if self._audit_hook:
            self._audit_hook(category, decision, details)

    def run(
        self,
        profile: LabTestProfile,
        confirm_state_change: bool = False,
        reset_after: bool = False,
    ) -> dict[str, Any]:
        profile.validate_checks()
        registration = self._store.get(profile.lab_name)
        if registration is None:
            raise LabTestError(f"Lab '{profile.lab_name}' is not registered; refusing to test.")
        self._audit("allow", f"lab '{profile.lab_name}' registered; profile accepted.")

        verify = self._manager.verify(profile.lab_name)
        if not verify.get("ok"):
            raise LabTestError(f"Lab '{profile.lab_name}' is not healthy: {verify}")
        self._audit("allow", f"lab health verified: {json.dumps(verify)[:300]}")

        # Resolve the target inside the lab network unless explicitly given.
        if not profile.base_url or profile.base_url in ("auto", "http://auto"):
            profile = profile.model_copy(
                update={"base_url": discover_service_base_url(self._manager, profile.lab_name)}
            )
            self._audit("info", f"target auto-discovered: {profile.base_url}")

        include_state = bool(profile.state_changing_checks()) and confirm_state_change
        if profile.state_changing_checks() and not confirm_state_change:
            self._audit(
                "deny",
                "state-changing checks requested without per-run confirmation; "
                "skipping synthetic_login.",
            )

        payload_path = self._write_payload(profile, include_state)
        script_dir = str(Path(lab_probe.__file__).resolve().parent)
        network = f"msai-lab-{profile.lab_name}-net"

        try:
            pull = self._client.run(["pull", PROBE_IMAGE], timeout=900.0)
            if not pull.ok:
                raise LabTestError(f"cannot pull {PROBE_IMAGE}: {pull.stderr[:200]}")
            result = self._client.run_scanner(
                PROBE_IMAGE,
                ["python3", "/analyzer/lab_probe.py", "/probe/payload.json"],
                host_path=str(payload_path.parent),
                container_path="/probe",
                extra_ro_mounts=[(script_dir, "/analyzer")],
                network_name=network,
                timeout=300.0,
            )
        except DockerCommandError as exc:
            raise LabTestError(f"docker failed: {exc}") from exc
        finally:
            payload_path.unlink(missing_ok=True)

        if not result.stdout.strip():
            raise LabTestError(f"lab probe exited {result.returncode}: {result.stderr[:300]}")
        try:
            report = json.loads(result.stdout.strip().splitlines()[-1])
        except json.JSONDecodeError as exc:
            raise LabTestError(f"unparseable probe output: {exc}") from exc
        if "error" in report:
            raise LabTestError(f"probe failed: {report['error']}")

        findings = self._to_findings(report)
        self._db.save_tool_run(
            ToolRunRecord(
                assessment_id=self._assessment_id,
                tool_name="lab.recon",
                exit_code=0,
                redacted_summary=json.dumps(report)[:900],
            )
        )
        for finding in findings:
            self._db.save_finding(finding.model_copy(update={"assessment_id": self._assessment_id}))
        self._audit(
            "allow",
            f"lab tests done: {len(report.get('results', []))} checks, "
            f"{len(findings)} findings (state-changing included: {include_state}).",
        )

        post = self._manager.verify(profile.lab_name)
        reset_report: dict[str, Any] | None = None
        if reset_after:
            reset_report = self._manager.reset(registration.profile)
            self._audit("allow", f"lab reset to baseline: {json.dumps(reset_report)[:200]}.")
        elif not post.get("ok"):
            self._audit("error", f"lab health degraded after tests: {post}")

        return {
            "lab": profile.lab_name,
            "probe": report,
            "findings": [f.model_dump() for f in findings],
            "post_verify": post,
            "reset": reset_report,
        }

    def _write_payload(self, profile: LabTestProfile, include_state: bool) -> Path:
        payload = build_probe_payload(profile, include_state)
        # The payload must reach the container as a file; lab subnets are
        # injected so the probe can validate its own destinations.
        data = json.loads(payload)
        data["lab_subnets"] = [
            r.profile.subnet_cidr for r in self._store.list() if r.profile.name == profile.lab_name
        ]
        stage = Path("/tmp") / f"msai-lab-payload-{self._assessment_id}"  # noqa: S108 - short-lived staging
        stage.mkdir(parents=True, exist_ok=True)
        path = stage / "payload.json"
        path.write_text(json.dumps(data))
        return path

    @staticmethod
    def _to_findings(report: dict[str, Any]) -> list[FindingRecord]:
        findings: list[FindingRecord] = []
        for result in report.get("results", []):
            check = result.get("check", "?")
            if not result.get("ok"):
                findings.append(
                    FindingRecord(
                        title=f"Lab check failed: {check}",
                        severity=Severity.INFO,
                        evidence=str(result.get("detail", ""))[:500],
                        remediation="Inspect the lab environment.",
                        tool_name="lab.recon",
                    )
                )
                continue
            if check == "security_headers":
                for header in result.get("missing", []):
                    findings.append(
                        FindingRecord(
                            title=f"Lab target missing security header: {header}",
                            severity=Severity.LOW,
                            evidence=f"GET {check}: header {header} absent.",
                            remediation=f"Add {header} on the lab application.",
                            tool_name="lab.recon",
                        )
                    )
            if check == "common_paths":
                for item in result.get("exposed", []):
                    findings.append(
                        FindingRecord(
                            title=f"Lab path exposed: {item['path']} (HTTP {item['status']})",
                            severity=Severity.MEDIUM,
                            evidence=f"GET {item['path']} -> {item['status']}.",
                            remediation="Remove or protect the exposed path.",
                            tool_name="lab.recon",
                        )
                    )
            if check == "synthetic_login":
                for attempt in result.get("attempts", []):
                    if attempt.get("synthetic_accepted"):
                        findings.append(
                            FindingRecord(
                                title=f"Authentication not enforced at {attempt['path']}",
                                severity=Severity.HIGH,
                                evidence=(
                                    f"POST {attempt['path']} with SYNTHETIC "
                                    "credentials was accepted "
                                    f"(HTTP {attempt.get('status')})."
                                ),
                                remediation="Enforce server-side authentication.",
                                tool_name="lab.validation",
                            )
                        )
        return findings

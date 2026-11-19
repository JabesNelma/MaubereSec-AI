"""CLI APK static analysis command (v0.6)."""

from __future__ import annotations

from typing import Annotated

import typer

from ..docker.client import DockerClient
from ..paths import database_path
from ..policy.gateway import PolicyDenied, PolicyGateway
from ..records import Mode, Scope, ScopeTarget, TargetKind, ToolRunRecord
from ..storage.db import Database
from ..storage.lab_store import LabStore
from ..tools.apk.analysis import ApkAnalyzerAdapter
from ..tools.apk.validate import ApkValidationError, quick_zip_probe, validate_apk_path
from ..tools.registry import default_registry

apk_app = typer.Typer(help="APK static analysis (v0.6).")


@apk_app.command("analyze")
def analyze(
    path: Annotated[str, typer.Argument(help="Path to the .apk file.")],
    inventory_only: Annotated[
        bool, typer.Option("--metadata-only", help="Validate + hash only; skip container analysis.")
    ] = False,
) -> None:
    """Statically analyze an APK. It is never installed or executed."""
    try:
        apk = validate_apk_path(path)
        quick_zip_probe(apk.path)
    except ApkValidationError as exc:
        typer.echo(f"Invalid APK: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    target_value = str(apk.path)
    scope = Scope(
        mode=Mode.LOCAL_FILE,
        targets=(ScopeTarget(kind=TargetKind.APK, value=target_value),),
    )
    db = Database(database_path())
    gateway = PolicyGateway(db, default_registry(), LabStore(db).policy_registry())
    try:
        assessment = gateway.authorize_assessment(scope, None)
    except PolicyDenied as exc:
        typer.echo(f"Blocked by policy: {exc}", err=True)
        db.close()
        raise typer.Exit(code=1) from exc

    typer.echo(f"Assessment {assessment.id} | mode=local_file | target={target_value}")
    typer.echo(f"SHA-256: {apk.sha256}  ({apk.size_bytes} bytes)")
    typer.echo("The APK is treated as untrusted data: never installed, never executed.")

    if inventory_only:
        db.save_tool_run(
            ToolRunRecord(
                assessment_id=assessment.id,
                tool_name="apk.metadata",
                exit_code=0,
                redacted_summary=f"sha256={apk.sha256} size={apk.size_bytes}",
            )
        )
        db.save_assessment(assessment.model_copy(update={"status": "completed"}))
        db.close()
        return

    client = DockerClient()
    if not client.available:
        typer.echo("docker CLI not found; cannot run the analyzer container.", err=True)
        db.save_assessment(assessment.model_copy(update={"status": "failed"}))
        db.close()
        raise typer.Exit(code=1)

    try:
        gateway.check_tool_call(assessment, "apk.static_review", target_value)
        typer.echo(f"running apk.static_review ({ApkAnalyzerAdapter.image}) …")
        report, findings = ApkAnalyzerAdapter(client).run(target_value, apk.sha256)
    except PolicyDenied as exc:
        typer.echo(f"Blocked by policy: {exc}", err=True)
        db.save_assessment(assessment.model_copy(update={"status": "failed"}))
        db.close()
        raise typer.Exit(code=1) from exc
    except Exception as exc:  # ScannerUnavailable surfaced generically
        typer.echo(f"Analysis failed: {exc}", err=True)
        db.save_tool_run(
            ToolRunRecord(
                assessment_id=assessment.id,
                tool_name="apk.static_review",
                exit_code=None,
                redacted_summary=f"failed: {exc}"[:500],
            )
        )
        db.save_assessment(assessment.model_copy(update={"status": "failed"}))
        db.close()
        raise typer.Exit(code=1) from exc

    manifest_raw = report.get("manifest", {})
    manifest = manifest_raw if isinstance(manifest_raw, dict) else {}
    summary = (
        f"package={manifest.get('package')} version={manifest.get('versionName')} "
        f"permissions={len(manifest.get('permissions', []))} "
        f"exported={manifest.get('exported_components')}"
    )
    db.save_tool_run(
        ToolRunRecord(
            assessment_id=assessment.id,
            tool_name="apk.static_review",
            exit_code=0,
            redacted_summary=summary[:1000],
        )
    )
    for finding in findings:
        db.save_finding(finding.model_copy(update={"assessment_id": assessment.id}))
    db.save_assessment(assessment.model_copy(update={"status": "completed"}))

    typer.echo(f"package={manifest.get('package')} version={manifest.get('versionName')}")
    typer.echo(f"permissions: {', '.join(manifest.get('permissions', [])[:15]) or 'none'}")
    typer.echo(f"\nFindings: {len(findings)}")
    for finding in findings:
        typer.echo(f"  [{finding.severity.value}/{finding.confidence.value}] {finding.title}")
    db.close()

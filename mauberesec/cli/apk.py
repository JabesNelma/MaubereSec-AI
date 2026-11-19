"""CLI APK static analysis command (v0.6)."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from ..android.emulator import (
    DEFAULT_EMULATOR_IMAGE,
    EmulatorRunError,
    EmulatorRunner,
    EmulatorSpec,
)
from ..android.hostcheck import (
    EmulatorUnsupportedError,
    detect_host,
    require_emulator_support,
)
from ..docker.client import DockerClient
from ..paths import database_path
from ..policy.gateway import PolicyDenied, PolicyGateway
from ..records import Mode, Scope, ScopeTarget, TargetKind, ToolRunRecord
from ..storage.db import Database
from ..storage.lab_store import LabStore
from ..tools.apk.analysis import ApkAnalyzerAdapter
from ..tools.apk.validate import ApkValidationError, quick_zip_probe, validate_apk_path
from ..tools.registry import default_registry

apk_app = typer.Typer(help="APK static analysis (v0.6) and experimental dynamic analysis (v0.9).")


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


@apk_app.command("dynamic")
def dynamic(
    path: Annotated[str, typer.Argument(help="Path to the .apk file.")],
    package: Annotated[
        str,
        typer.Option("--package", help="Android package name to launch (e.g. com.example.app)."),
    ] = "",
    image: Annotated[
        str, typer.Option("--image", help="Disposable emulator container image.")
    ] = DEFAULT_EMULATOR_IMAGE,
    logcat_seconds: Annotated[int, typer.Option("--logcat-seconds", min=5, max=300)] = 20,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Check prerequisites and print the plan; run nothing.")
    ] = False,
) -> None:
    """EXPERIMENTAL: run an APK in a disposable Android emulator (isolated network).

    Requires host virtualization support; refuses clearly otherwise rather
    than degrading isolation. The APK is never installed on a personal
    device: every adb call runs inside the disposable container.
    """
    try:
        apk = validate_apk_path(path)
        quick_zip_probe(apk.path)
    except ApkValidationError as exc:
        typer.echo(f"Invalid APK: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    capability = detect_host()
    typer.echo(f"host: {capability.summary()}")
    if not capability.emulator_supported:
        try:
            require_emulator_support(capability)
        except EmulatorUnsupportedError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=3) from exc

    resolved_package = package or _guess_package(apk.path)
    typer.echo(
        f"plan: image={image} network=internal-eval-only package={resolved_package} "
        f"apk={apk.path.name} (sha256 {apk.sha256[:12]}…)"
    )
    typer.echo(
        "note: dynamic analysis is EXPERIMENTAL; synthetic dataset only; "
        "emulator reset is verified per run."
    )
    if dry_run:
        typer.echo("dry-run: nothing executed.")
        return

    if not resolved_package:
        typer.echo(
            "Cannot determine the package name; pass --package <name> for dynamic analysis.",
            err=True,
        )
        raise typer.Exit(code=2)

    client = DockerClient()
    if not client.available:
        typer.echo("docker CLI not found; cannot start the emulator.", err=True)
        raise typer.Exit(code=1)

    from ..paths import database_path
    from ..records import (
        AssessmentRecord,
        Mode,
        Scope,
        ScopeTarget,
        TargetKind,
        ToolRunRecord,
    )

    db = Database(database_path())
    scope = Scope(
        mode=Mode.LOCAL_FILE,
        targets=(ScopeTarget(kind=TargetKind.APK, value=str(apk.path)),),
    )
    assessment = AssessmentRecord(mode=scope.mode, scope=scope)
    db.save_assessment(assessment)

    runner = EmulatorRunner(client)
    spec = EmulatorSpec(
        apk_path=apk.path,
        package=resolved_package,
        image=image,
        logcat_seconds=logcat_seconds,
    )
    try:
        report = runner.run(spec, capability)
    except (EmulatorRunError, EmulatorUnsupportedError) as exc:
        typer.echo(f"Dynamic analysis failed: {exc}", err=True)
        db.save_assessment(assessment.model_copy(update={"status": "failed"}))
        db.close()
        raise typer.Exit(code=1) from exc

    db.save_tool_run(
        ToolRunRecord(
            assessment_id=assessment.id,
            tool_name="apk.dynamic_emulator",
            exit_code=0,
            redacted_summary=report.summary()[:900],
        )
    )
    from ..records import AuditEventRecord

    db.save_audit_event(
        AuditEventRecord(
            assessment_id=assessment.id,
            category="apk_dynamic",
            decision="allow",
            details=report.summary()[:500],
        )
    )
    db.save_assessment(assessment.model_copy(update={"status": "completed"}))
    db.close()

    typer.echo(report.summary())
    logcat_lines = report.emulator.get("logcat_lines")
    typer.echo(f"logcat lines captured: {logcat_lines}")
    for note in report.notes:
        typer.echo(f"  note: {note}")


def _guess_package(apk_path: Path) -> str:
    """Derive the package name via the static analyzer (never executes the APK)."""
    try:
        from ..tools.apk.container.apk_analyzer import analyze_apk

        report = analyze_apk(str(apk_path))
        pkg = (report.get("manifest") or {}).get("package")
        return str(pkg) if pkg else ""
    except Exception:
        return ""

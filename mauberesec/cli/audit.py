"""CLI source-code audit command (v0.5): LOCAL_FILE mode, containerized scanners."""

from __future__ import annotations

from typing import Annotated

import typer

from ..docker.client import DockerClient
from ..paths import database_path
from ..policy.gateway import PolicyDenied, PolicyGateway
from ..records import Mode, Scope, ScopeTarget, TargetKind, ToolRunRecord
from ..scope.pathcheck import PathError_, canonicalize_repo_path
from ..storage.db import Database
from ..storage.lab_store import LabStore
from ..tools.registry import default_registry
from ..tools.source_audit.adapters import (
    ScannerUnavailable,
    dedup_findings,
    default_adapters,
)
from ..tools.source_audit.inventory import InventoryLimitError, build_inventory
from ..tools.source_audit.manifest import analyze_manifests


def audit(
    path: Annotated[str, typer.Argument(help="Repository root to audit (local path).")],
    skip_scanners: Annotated[
        bool,
        typer.Option(
            "--inventory-only", help="Skip container scanners; inventory + manifests only."
        ),
    ] = False,
) -> None:
    """Audit a local repository: inventory, manifests, and containerized scanners."""
    try:
        canonical = canonicalize_repo_path(path)
    except PathError_ as exc:
        typer.echo(f"Invalid repository path: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    target_value = str(canonical.root)
    scope = Scope(
        mode=Mode.LOCAL_FILE,
        targets=(ScopeTarget(kind=TargetKind.REPO, value=target_value),),
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
    typer.echo("Project code will NOT be executed; dependencies will NOT be installed.")

    # -- inventory ------------------------------------------------------------
    try:
        inventory = build_inventory(canonical.root)
    except InventoryLimitError as exc:
        typer.echo(f"Stopped: {exc}", err=True)
        db.save_assessment(assessment.model_copy(update={"status": "failed"}))
        db.close()
        raise typer.Exit(code=1) from exc
    db.save_tool_run(
        ToolRunRecord(
            assessment_id=assessment.id,
            tool_name="source.inventory",
            exit_code=0,
            redacted_summary=inventory.summary(),
        )
    )
    typer.echo(inventory.summary())
    if inventory.secret_hint_files:
        typer.echo(
            f"Secret-hint files (excluded from any cloud context): "
            f"{', '.join(inventory.secret_hint_files[:10])}"
        )

    # -- manifests ---------------------------------------------------------------
    for summary in analyze_manifests(canonical.root):
        typer.echo(summary.render())

    # -- containerized scanners ----------------------------------------------------
    findings = []
    if skip_scanners:
        typer.echo("Scanners skipped (--inventory-only).")
    else:
        client = DockerClient()
        if not client.available:
            typer.echo("docker CLI not found; skipping container scanners.", err=True)
        else:
            for adapter in default_adapters(client):
                try:
                    gateway.check_tool_call(assessment, adapter.name, target_value)
                except PolicyDenied as exc:
                    typer.echo(f"skip {adapter.name}: {exc}", err=True)
                    continue
                try:
                    typer.echo(f"running {adapter.name} ({adapter.image}) …")
                    scanner_findings = adapter.run(target_value)
                except ScannerUnavailable as exc:
                    typer.echo(f"warning: {adapter.name} unavailable: {exc}", err=True)
                    db.save_tool_run(
                        ToolRunRecord(
                            assessment_id=assessment.id,
                            tool_name=adapter.name,
                            exit_code=None,
                            redacted_summary=f"unavailable: {exc}"[:500],
                        )
                    )
                    continue
                db.save_tool_run(
                    ToolRunRecord(
                        assessment_id=assessment.id,
                        tool_name=adapter.name,
                        exit_code=0,
                        redacted_summary=f"{len(scanner_findings)} raw findings",
                    )
                )
                findings.extend(scanner_findings)

    unique = dedup_findings(findings)
    for finding in unique:
        db.save_finding(finding.model_copy(update={"assessment_id": assessment.id}))
    db.save_assessment(assessment.model_copy(update={"status": "completed"}))

    typer.echo(f"\nFindings (deduplicated): {len(unique)}")
    for finding in unique:
        typer.echo(
            f"  [{finding.severity.value}/{finding.confidence.value}] "
            f"{finding.title} ({finding.tool_name})"
        )
    db.close()

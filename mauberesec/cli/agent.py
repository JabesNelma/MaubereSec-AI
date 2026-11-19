"""CLI commands: plan + agent run (v0.7)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

import typer

from ..agent.executor import BoundedAgent
from ..agent.planner import Planner, plan_disclosure
from ..agent.state import AgentState
from ..ai import manager
from ..ai.base import ModelProvider
from ..config.settings import load_settings
from ..docker.client import DockerClient
from ..paths import database_path
from ..policy.gateway import PolicyDenied, PolicyGateway
from ..records import (
    AssessmentRecord,
    AuthorizationRecord,
    Mode,
    ResourceBudget,
    Scope,
    ScopeTarget,
    TargetKind,
)
from ..scope.pathcheck import PathError_, canonicalize_repo_path
from ..scope.urlcheck import UrlError, normalize_url
from ..storage.db import Database
from ..storage.lab_store import LabStore
from ..tools.apk.validate import ApkValidationError, quick_zip_probe, validate_apk_path
from ..tools.registry import default_registry

agent_app = typer.Typer(help="Bounded agent planning and execution (v0.7).")


def _resolve_scope(target: str) -> tuple[Scope, str]:
    """Classify a CLI target into a scope (mirrors scan/audit rules)."""
    if "://" in target or (":" in target and target.split("/")[0].count(":") == 1):
        try:
            normalized = normalize_url(target)
        except UrlError as exc:
            typer.echo(f"Invalid URL: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        db = Database(database_path())
        labs = LabStore(db).policy_registry()
        db.close()
        mode = Mode.LOCAL_LAB if labs.is_registered(normalized.host) else Mode.LIVE_WHITE_HAT
        scope = Scope(
            mode=mode,
            targets=(ScopeTarget(kind=TargetKind.WEBSITE, value=normalized.host_port),),
        )
        return scope, "web"
    path = Path(target)
    if path.suffix.lower() == ".apk":
        try:
            apk = validate_apk_path(target)
            quick_zip_probe(apk.path)
        except ApkValidationError as exc:
            typer.echo(f"Invalid APK: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        scope = Scope(
            mode=Mode.LOCAL_FILE,
            targets=(ScopeTarget(kind=TargetKind.APK, value=str(apk.path)),),
        )
        return scope, "apk"
    try:
        canonical = canonicalize_repo_path(target)
    except PathError_ as exc:
        typer.echo(f"Invalid path: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    scope = Scope(
        mode=Mode.LOCAL_FILE,
        targets=(ScopeTarget(kind=TargetKind.REPO, value=str(canonical.root)),),
    )
    return scope, "repo"


def _authorize(
    db: Database,
    scope: Scope,
    auth_reference: str | None,
    authorized_by: str | None,
) -> tuple[PolicyGateway, AssessmentRecord]:
    authorization = None
    if scope.mode == Mode.LIVE_WHITE_HAT:
        if not (auth_reference and authorized_by):
            typer.echo("Live assessment requires --auth-reference and --authorized-by.", err=True)
            raise typer.Exit(code=2)
        authorization = AuthorizationRecord(
            reference=auth_reference,
            scope_sha256=scope.sha256(),
            authorized_by=authorized_by,
            valid_until=datetime.now(UTC) + timedelta(hours=24),
        )
    gateway = PolicyGateway(db, default_registry(), LabStore(db).policy_registry())
    try:
        return gateway, gateway.authorize_assessment(scope, authorization)
    except PolicyDenied as exc:
        typer.echo(f"Blocked by policy: {exc}", err=True)
        db.close()
        raise typer.Exit(code=1) from exc


def _build_planner(use_ai: bool, audit_hook: Any) -> tuple[Planner, ModelProvider | None, str]:
    provider = None
    model = "?"
    if use_ai:
        settings = load_settings()
        if not settings.is_configured:
            typer.echo(
                "AI planner requested but provider/model/key are not configured; "
                "no fallback provider is used.",
                err=True,
            )
            raise typer.Exit(code=2)
        provider = manager.build_provider(settings)
        model = settings.model or "?"
    return (
        Planner(default_registry(), ResourceBudget(), provider, audit_hook=audit_hook),
        provider,
        model,
    )


@agent_app.command("plan")
def plan(
    target: Annotated[str, typer.Argument(help="URL, repository path, or .apk file.")],
    goal: Annotated[str | None, typer.Option("--goal", help="Assessment goal text.")] = None,
    use_ai: Annotated[
        bool, typer.Option("--use-ai", help="Let the cloud model propose the plan.")
    ] = False,
    auth_reference: Annotated[str | None, typer.Option("--auth-reference")] = None,
    authorized_by: Annotated[str | None, typer.Option("--authorized-by")] = None,
) -> None:
    """Generate (and show) a bounded assessment plan without executing it."""
    scope, kind = _resolve_scope(target)
    db = Database(database_path())
    _, assessment = _authorize(db, scope, auth_reference, authorized_by)

    def audit(category: str, decision: str, details: str) -> None:
        from ..records import AuditEventRecord

        db.save_audit_event(
            AuditEventRecord(
                assessment_id=assessment.id,
                category=category,
                decision=decision,
                details=details,
            )
        )

    planner, provider, model = _build_planner(use_ai, audit)
    typer.echo(plan_disclosure(provider, model))
    plan_obj = planner.build_plan(goal or f"assess {kind} target", scope)
    from ..agent.schemas import plan_to_prompt_context

    typer.echo(f"plan created_by={plan_obj.created_by} steps={len(plan_obj.steps)}:")
    typer.echo(plan_to_prompt_context(plan_obj))
    db.save_assessment(assessment.model_copy(update={"status": "cancelled"}))
    db.close()


@agent_app.command("run")
def run(
    target: Annotated[str, typer.Argument(help="URL, repository path, or .apk file.")],
    goal: Annotated[str | None, typer.Option("--goal")] = None,
    use_ai: Annotated[bool, typer.Option("--use-ai")] = False,
    max_steps: Annotated[int, typer.Option("--max-steps", min=1, max=100)] = 25,
    auth_reference: Annotated[str | None, typer.Option("--auth-reference")] = None,
    authorized_by: Annotated[str | None, typer.Option("--authorized-by")] = None,
) -> None:
    """Plan and execute a bounded assessment (Ctrl+C keeps partial results)."""
    scope, kind = _resolve_scope(target)
    db = Database(database_path())
    gateway, assessment = _authorize(db, scope, auth_reference, authorized_by)

    def audit(category: str, decision: str, details: str) -> None:
        from ..records import AuditEventRecord

        db.save_audit_event(
            AuditEventRecord(
                assessment_id=assessment.id,
                category=category,
                decision=decision,
                details=details,
            )
        )

    planner, provider, model = _build_planner(use_ai, audit)
    typer.echo(plan_disclosure(provider, model))
    plan_obj = planner.build_plan(goal or f"assess {kind} target", scope)
    typer.echo(f"plan: {len(plan_obj.steps)} steps (created_by={plan_obj.created_by})")

    budget = ResourceBudget(max_steps=min(max_steps, 100))
    client = DockerClient()
    from ..agent.executors_builtin import default_executor_registry

    lab_subnets = [r.profile.subnet_cidr for r in LabStore(db).list()]
    executors = default_executor_registry(client if client.available else None, lab_subnets)

    state = AgentState(budget)
    agent = BoundedAgent(db, gateway, default_registry(), executors, budget, state=state)
    try:
        report = agent.run(assessment, plan_obj)
    except KeyboardInterrupt:
        state.cancel.set()
        typer.echo("\nCancelled — partial results preserved.", err=True)

        db.save_assessment(assessment.model_copy(update={"status": "cancelled"}))
        db.save_audit_event(
            __import__("mauberesec.records", fromlist=["AuditEventRecord"]).AuditEventRecord(
                assessment_id=assessment.id,
                category="run_finish",
                decision="info",
                details="cancelled by KeyboardInterrupt; partial results preserved.",
            )
        )
        db.close()
        raise typer.Exit(code=130) from None

    typer.echo(report.summary())
    db.close()

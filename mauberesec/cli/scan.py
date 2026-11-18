"""CLI passive scan command (v0.4): live requires authorization, lab via registry."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

import httpx
import typer

from ..paths import database_path
from ..policy.gateway import PolicyDenied, PolicyGateway
from ..records import (
    AssessmentRecord,
    AuthorizationRecord,
    Mode,
    Scope,
    ScopeTarget,
    TargetKind,
)
from ..scope.urlcheck import (
    DestinationError,
    UrlError,
    normalize_url,
    validate_lab_destination,
    validate_live_destination,
)
from ..storage.db import Database
from ..storage.lab_store import LabStore
from ..tools.registry import default_registry
from ..tools.website.passive import (
    BudgetExhaustedError,
    PassiveHttpChecker,
)


def scan(
    url: Annotated[str, typer.Argument(help="Target URL (https://example.com).")],
    auth_reference: Annotated[
        str | None,
        typer.Option(
            "--auth-reference", help="Written authorization reference (required for live)."
        ),
    ] = None,
    authorized_by: Annotated[
        str | None, typer.Option("--authorized-by", help="Who granted the authorization.")
    ] = None,
) -> None:
    """Run a passive assessment against an authorized live target or a registered lab."""
    try:
        normalized = normalize_url(url)
    except UrlError as exc:
        typer.echo(f"Invalid URL: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    db = Database(database_path())
    store = LabStore(db)
    lab_registry = store.policy_registry()

    # Classify: registered lab subnet -> LOCAL_LAB, otherwise live (fail closed).
    is_lab = _host_in_labs(normalized.host, store)
    if is_lab:
        mode = Mode.LOCAL_LAB
    else:
        mode = Mode.LIVE_WHITE_HAT
        if not (auth_reference and authorized_by):
            typer.echo(
                "Live assessment requires explicit authorization: provide "
                "--auth-reference and --authorized-by (see docs/SECURITY_POLICY.md).",
                err=True,
            )
            raise typer.Exit(code=2)

    target_value = normalized.host_port
    scope = Scope(
        mode=mode,
        targets=(ScopeTarget(kind=TargetKind.WEBSITE, value=target_value),),
    )

    authorization: AuthorizationRecord | None = None
    if mode == Mode.LIVE_WHITE_HAT:
        authorization = AuthorizationRecord(
            reference=auth_reference or "",
            scope_sha256=scope.sha256(),
            authorized_by=authorized_by or "",
            valid_until=datetime.now(UTC) + timedelta(hours=24),
        )

    gateway = PolicyGateway(db, default_registry(), lab_registry)
    try:
        assessment = gateway.authorize_assessment(scope, authorization)
    except PolicyDenied as exc:
        typer.echo(f"Blocked by policy: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    # Destination validation right before any request.
    validator = (
        (lambda u: validate_lab_destination(u, [r.profile.subnet_cidr for r in store.list()]))
        if mode == Mode.LOCAL_LAB
        else validate_live_destination
    )
    try:
        validator(normalized)
    except DestinationError as exc:
        typer.echo(f"Destination rejected: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(f"Assessment {assessment.id} | mode={mode.value} | target={target_value}")
    typer.echo("Passive checks only: GET requests, no credentials, redirect revalidation.")

    checker = PassiveHttpChecker(validate_destination=validator)
    try:
        evidence, findings = checker.check(str(normalized))
    except (DestinationError, BudgetExhaustedError) as exc:
        typer.echo(f"Stopped: {exc}", err=True)
        _finish(db, assessment, "failed")
        raise typer.Exit(code=1) from exc
    except httpx.HTTPError as exc:
        typer.echo(
            f"Cannot reach target (lab networks are internal; run checks from the "
            f"lab network): {exc}",
            err=True,
        )
        _finish(db, assessment, "failed")
        raise typer.Exit(code=1) from exc
    finally:
        checker.close()

    from ..records import ToolRunRecord

    db.save_tool_run(
        ToolRunRecord(
            assessment_id=assessment.id,
            tool_name="passive.http_headers",
            exit_code=0,
            redacted_summary=evidence.summary()[:2000],
        )
    )
    for finding in findings:
        db.save_finding(finding.model_copy(update={"assessment_id": assessment.id}))

    typer.echo(evidence.summary())
    typer.echo(f"\nFindings: {len(findings)}")
    for finding in findings:
        typer.echo(f"  [{finding.severity.value}] {finding.title}")
    _finish(db, assessment, "completed")


def _host_in_labs(host: str, store: LabStore) -> bool:
    return store.policy_registry().is_registered(host)


def _finish(db: Database, assessment: AssessmentRecord, status: str) -> None:
    updated = assessment.model_copy(update={"status": status})
    db.save_assessment(updated)
    db.close()

"""CLI commands for local lab management (v0.3)."""

from __future__ import annotations

import json

import typer

from ..docker.client import DockerClient, DockerCommandError
from ..docker.labs import LabManager, LabProfile, LabStateError, builtin_profiles
from ..paths import database_path
from ..storage.db import Database
from ..storage.lab_store import LabStore

lab_app = typer.Typer(help="Manage disposable local training labs.")


def _manager_and_store() -> tuple[LabManager, LabStore]:
    client = DockerClient()
    if not client.available:
        typer.echo("docker CLI not found on PATH.", err=True)
        raise typer.Exit(code=1)
    db = Database(database_path())
    return LabManager(client), LabStore(db)


def _known_profiles() -> dict[str, LabProfile]:
    return builtin_profiles()


@lab_app.command("list")
def list_labs() -> None:
    """List lab templates and persisted registrations."""
    profiles = _known_profiles()
    _, store = _manager_and_store()
    registered = {r.profile.name for r in store.list()}
    if not profiles:
        typer.echo("No lab templates available.")
        return
    for name, profile in sorted(profiles.items()):
        mark = "registered" if name in registered else "not registered"
        typer.echo(f"{name} [{mark}] {profile.subnet_cidr} — {profile.description}")


@lab_app.command("register")
def register_lab(
    name: str = typer.Argument(help="Lab template name (see 'lab list')."),
) -> None:
    """Create the lab from its template and register it for policy use."""
    profiles = _known_profiles()
    if name not in profiles:
        available = ", ".join(sorted(profiles))
        typer.echo(f"Unknown lab template '{name}'. Available: {available}.", err=True)
        raise typer.Exit(code=2) from None
    manager, store = _manager_and_store()
    profile = profiles[name]
    try:
        created = manager.create(profile)
    except (LabStateError, DockerCommandError) as exc:
        typer.echo(f"Lab creation failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    store.register(profile)
    typer.echo(f"Lab '{name}' created (network {profile.network_name()}).")
    typer.echo(f"Containers: {', '.join(created) or 'none'}")
    typer.echo("Registered for Local Lab policy classification.")


@lab_app.command("verify")
def verify_lab(name: str = typer.Argument(help="Registered lab name.")) -> None:
    """Verify network, labels, container state, and health for a lab."""
    manager, store = _manager_and_store()
    if store.get(name) is None:
        typer.echo(f"Lab '{name}' is not registered.", err=True)
        raise typer.Exit(code=2)
    report = manager.verify(name)
    typer.echo(json.dumps(report, indent=2))
    raise typer.Exit(code=0 if report.get("ok") else 1)


@lab_app.command("teardown")
def teardown_lab(name: str = typer.Argument(help="Registered lab name.")) -> None:
    """Remove only the resources created by this lab's profile."""
    manager, store = _manager_and_store()
    if store.get(name) is None:
        typer.echo(f"Lab '{name}' is not registered.", err=True)
        raise typer.Exit(code=2)
    report = manager.teardown(name)
    store.unregister(name)
    typer.echo(f"Removed: {', '.join(report['removed']) or 'nothing'}")
    typer.echo("Lab registration removed.")


@lab_app.command("test")
def test_lab(
    name: str = typer.Argument(help="Registered lab name."),
    base_url: str = typer.Option(
        "",
        "--base-url",
        help="Target base URL inside the lab; auto-discovered from the lab network when omitted.",
    ),
    confirm_state_change: bool = typer.Option(
        False,
        "--confirm-state-change",
        help="Explicitly confirm state-changing checks (synthetic login probe).",
    ),
    reset_after: bool = typer.Option(
        False, "--reset-after", help="Reset the lab to baseline after the tests."
    ),
    assessment_id: str = typer.Option(
        "", "--assessment-id", help="Attach results to an existing assessment."
    ),
) -> None:
    """Run controlled red-team validation against a registered disposable lab."""

    from ..labs.profiles import default_profile
    from ..labs.runner import LabTestError, LabValidationRunner
    from ..records import AssessmentRecord

    manager, store = _manager_and_store()
    reg = store.get(name)
    if reg is None:
        typer.echo(f"Lab '{name}' is not registered.", err=True)
        raise typer.Exit(code=2)

    db = Database(database_path())
    if assessment_id and db.get_assessment(assessment_id):
        assessment = db.get_assessment(assessment_id)
        assert assessment is not None
    else:
        from ..records import Mode, Scope, ScopeTarget, TargetKind

        if base_url:
            host = base_url.split("//")[-1].split("/")[0]
        else:
            host = reg.profile.subnet_cidr  # lab subnet identifies the target
        scope = Scope(
            mode=Mode.LOCAL_LAB,
            targets=(ScopeTarget(kind=TargetKind.WEBSITE, value=host),),
        )
        assessment = AssessmentRecord(mode=scope.mode, scope=scope)
        db.save_assessment(assessment)

    profile = default_profile(name, base_url or "auto")
    runner = LabValidationRunner(db, manager._docker, assessment.id)
    try:
        report = runner.run(
            profile,
            confirm_state_change=confirm_state_change,
            reset_after=reset_after,
        )
    except (LabTestError, LabStateError) as exc:
        typer.echo(f"Lab test failed: {exc}", err=True)
        db.close()
        raise typer.Exit(code=1) from exc

    typer.echo(f"Lab '{name}' test report (assessment {assessment.id}):")
    for result in report["probe"].get("results", []):
        typer.echo(
            f"  [{result.get('check')}] ok={result.get('ok')} "
            f"{json.dumps(result.get('detail', result))[:160]}"
        )
    findings = report.get("findings", [])
    typer.echo(f"\nFindings: {len(findings)}")
    for finding in findings:
        typer.echo(f"  [{finding['severity']}] {finding['title']}")
    if report.get("reset"):
        typer.echo("Lab reset to baseline: yes")
    db.close()


@lab_app.command("reset")
def reset_lab(name: str = typer.Argument(help="Registered lab name.")) -> None:
    """Tear down and recreate the lab from its template."""
    manager, store = _manager_and_store()
    reg = store.get(name)
    if reg is None:
        typer.echo(f"Lab '{name}' is not registered.", err=True)
        raise typer.Exit(code=2)
    report = manager.reset(reg.profile)
    typer.echo(f"Removed: {', '.join(report['removed']) or 'nothing'}")
    typer.echo("Lab recreated and still registered.")

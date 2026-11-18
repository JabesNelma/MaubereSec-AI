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

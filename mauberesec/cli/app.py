"""Typer CLI application for MaubereSec AI (v0.1 scope).

Commands: --help, --version, doctor, config show, models list, models test.
No scanners, agent loops, or tool execution in this milestone.
"""

from __future__ import annotations

import shutil
import sys
from typing import Annotated

import typer

from .. import __version__
from ..ai import manager
from ..ai.base import ModelProvider, ProviderError
from ..ai.disclosure import disclosure_text
from ..config.settings import (
    ENV_MODEL,
    ENV_PROVIDER,
    CloudSettings,
    SettingsError,
    load_settings,
    provider_api_key_env,
    sys_platform,
)
from ..logging_setup import configure_logging, get_logger

app = typer.Typer(
    name="mauberesec",
    help="MaubereSec AI — AI security assessment agent (v0.1: CLI and cloud model foundation).",
    no_args_is_help=True,
    add_completion=False,
)
models_app = typer.Typer(help="Inspect and test configured cloud models.")
config_app = typer.Typer(help="Show resolved configuration.")
app.add_typer(models_app, name="models")
app.add_typer(config_app, name="config")
from .agent import agent_app  # noqa: E402 - avoids circular import at module top
from .apk import apk_app  # noqa: E402 - avoids circular import at module top
from .audit import audit as audit_command  # noqa: E402 - avoids circular import at module top
from .lab import lab_app  # noqa: E402 - avoids circular import at module top
from .scan import scan as scan_command  # noqa: E402 - avoids circular import at module top

app.add_typer(agent_app, name="agent")
app.add_typer(apk_app, name="apk")
app.add_typer(lab_app, name="lab")
app.command(name="scan")(scan_command)
app.command(name="audit")(audit_command)

log = get_logger("mauberesec.cli")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"mauberesec {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version", callback=_version_callback, is_eager=True, help="Print version and exit."
        ),
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", help="Enable debug logging.")] = False,
) -> None:
    configure_logging(verbose=verbose)


# -- doctor ------------------------------------------------------------------


@app.command()
def doctor() -> None:
    """Check the runtime environment and report platform limitations."""
    checks: list[tuple[str, bool, str]] = []

    checks.append(("python", True, f"Python {sys.version.split()[0]} on {sys_platform()}"))

    docker_path = shutil.which("docker")
    if docker_path:
        checks.append(("docker-cli", True, docker_path))
    else:
        checks.append(("docker-cli", False, "docker not found on PATH"))

    if docker_path:
        import subprocess

        result = subprocess.run(  # noqa: S603 - fixed args, path from shutil.which
            [docker_path, "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0:
            checks.append(("docker-daemon", True, f"server {result.stdout.strip()}"))
        else:
            checks.append(("docker-daemon", False, "daemon unreachable"))

    compose_ok = shutil.which("docker-compose") is not None
    if not compose_ok and docker_path:
        import subprocess

        probe = subprocess.run(  # noqa: S603 - fixed args, path from shutil.which
            [docker_path, "compose", "version"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        compose_ok = probe.returncode == 0
    checks.append(
        (
            "docker-compose",
            compose_ok,
            "available"
            if compose_ok
            else "docker compose plugin not found — container workflows limited",
        )
    )

    try:
        from ..android.hostcheck import detect_host

        capability = detect_host()
        checks.append(
            (
                "android-emulator",
                capability.emulator_supported,
                capability.summary().replace("emulator: ", ""),
            )
        )
    except Exception:
        checks.append(("android-emulator", False, "detection failed"))

    try:
        settings = load_settings()
        cloud = settings.is_configured
        detail = (
            f"provider={settings.provider or 'unset'}, model={settings.model or 'unset'}, "
            f"key env={provider_api_key_env(settings.provider or 'openai')} "
            f"({'set' if settings.api_key else 'unset'})"
        )
        checks.append(("cloud-config", cloud, detail))
    except SettingsError as exc:
        checks.append(("cloud-config", False, str(exc)))

    typer.echo(f"mauberesec {__version__} doctor")
    failed = False
    for name, ok, detail in checks:
        mark = "OK " if ok else "FAIL"
        if not ok:
            failed = True
        typer.echo(f"  [{mark}] {name}: {detail}")
    typer.echo(
        "Note: scanner execution, agent tool calls, and lab management are not included in v0.1."
    )
    raise typer.Exit(code=1 if failed else 0)


# -- config -------------------------------------------------------------------


@config_app.command("show")
def config_show() -> None:
    """Show the resolved (secret-free) configuration."""
    try:
        settings = load_settings()
    except SettingsError as exc:
        typer.echo(f"Configuration error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(f"provider: {settings.provider or '<unset>'}")
    typer.echo(f"model:    {settings.model or '<unset>'}")
    key_set = "set" if settings.api_key else "unset"
    key_env = provider_api_key_env(settings.provider or "openai")
    typer.echo(f"api key:  {key_set} ({key_env}; value never shown)")
    typer.echo(f"timeout:  {settings.timeout_seconds}s")
    typer.echo(f"config via env: {ENV_PROVIDER}, {ENV_MODEL}")


# -- models -------------------------------------------------------------------


@models_app.command("list")
def models_list() -> None:
    """List models offered by the configured provider."""
    settings = load_settings_or_exit()
    typer.echo(disclosure_text(settings.provider or "?", settings.model or "?"), err=True)
    provider = manager.build_provider(settings)
    try:
        for m in provider.list_models():
            typer.echo(m.model_id)
    finally:
        close_provider(provider)


@models_app.command("test")
def models_test() -> None:
    """Verify credentials, connectivity, and selected model availability."""
    settings = load_settings_or_exit()
    typer.echo(disclosure_text(settings.provider or "?", settings.model or "?"), err=True)
    provider = manager.build_provider(settings)
    try:
        info = provider.health_check()
        typer.echo(f"OK: provider={info.provider} model={info.model_id} reachable and authorized.")
    except ProviderError as exc:
        typer.echo(f"FAILED: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        close_provider(provider)


# -- helpers ------------------------------------------------------------------


def load_settings_or_exit() -> CloudSettings:
    try:
        settings = load_settings()
    except SettingsError as exc:
        typer.echo(f"Configuration error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    missing = []
    if not settings.provider:
        missing.append(ENV_PROVIDER)
    if not settings.model:
        missing.append(ENV_MODEL)
    if not settings.api_key:
        missing.append(provider_api_key_env(settings.provider or "openai"))
    if missing:
        typer.echo(
            f"Incomplete configuration: missing {', '.join(missing)}. "
            "No fallback provider is used.",
            err=True,
        )
        raise typer.Exit(code=2)
    return settings


def close_provider(provider: ModelProvider) -> None:
    close = getattr(provider, "close", None)
    if callable(close):
        close()


def run() -> None:
    try:
        app()
    except KeyboardInterrupt:
        typer.echo("Cancelled.", err=True)
        raise typer.Exit(code=130) from None


if __name__ == "__main__":
    run()

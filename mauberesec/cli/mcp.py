"""CLI commands for MCP integrations (v0.10)."""

from __future__ import annotations

import json
from typing import Annotated

import typer

from ..mcp.bridge import McpBridge, McpNotConfiguredError
from ..mcp.client import McpClientError, sdk_available
from ..mcp.config import McpConfigError, config_path
from ..paths import database_path
from ..storage.db import Database

mcp_app = typer.Typer(help="MCP integrations (explicit config only; nothing auto-connects).")


@mcp_app.command("list")
def list_servers() -> None:
    """Show configured MCP servers and their discovered (read-only) tools."""
    if not sdk_available():
        typer.echo("Official MCP SDK not installed: pip install mcp", err=True)
        raise typer.Exit(code=2)
    db = Database(database_path())
    try:
        bridge = McpBridge(db)
    except McpConfigError as exc:
        typer.echo(f"MCP config error: {exc}", err=True)
        db.close()
        raise typer.Exit(code=2) from exc

    servers = bridge.configured_servers()
    if not servers:
        typer.echo(f"No MCP servers configured ({config_path()}). Nothing is contacted.")
        db.close()
        return
    for server in servers:
        typer.echo(
            f"{server.name} trusted={server.trusted} read_only={server.read_only} "
            f"cmd={server.command}"
        )
        try:
            discovered = bridge.discover(server.name)
        except (McpClientError, McpNotConfiguredError) as exc:
            typer.echo(f"  discovery failed: {exc}", err=True)
            continue
        typer.echo(
            f"  server: {discovered.server_name} v{discovered.server_version} "
            f"(protocol {discovered.protocol_version or 'n/a'})"
        )
        for tool in discovered.tools:
            typer.echo(f"  tool: {tool.name} — {tool.description[:80]}")
        for rejected in discovered.rejected:
            typer.echo(f"  REJECTED: {rejected}")
    db.close()


@mcp_app.command("call")
def call_tool(
    server: Annotated[str, typer.Argument(help="Configured MCP server name.")],
    tool: Annotated[str, typer.Argument(help="MCP tool name as discovered.")],
    arguments: Annotated[str, typer.Option("--args", help="JSON object of tool arguments.")] = "{}",
) -> None:
    """Invoke a read-only MCP tool (policy-checked; untrusted servers refused)."""
    try:
        parsed = json.loads(arguments)
    except json.JSONDecodeError as exc:
        typer.echo(f"--args must be a JSON object: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if not isinstance(parsed, dict):
        typer.echo("--args must be a JSON object.", err=True)
        raise typer.Exit(code=2)

    db = Database(database_path())
    bridge = McpBridge(db)
    try:
        bridge.discover(server)  # register contracts before the policy check
        result = bridge.call_tool(server, tool, parsed)
    except (McpNotConfiguredError, McpClientError) as exc:
        typer.echo(f"MCP call failed: {exc}", err=True)
        db.close()
        raise typer.Exit(code=2) from exc
    except Exception as exc:  # PolicyDenied
        typer.echo(f"Blocked by policy: {exc}", err=True)
        db.close()
        raise typer.Exit(code=1) from exc

    typer.echo("--- untrusted server output (data only) ---")
    typer.echo(result.text)
    if result.is_error:
        typer.echo("(server reported an error)", err=True)
    db.close()

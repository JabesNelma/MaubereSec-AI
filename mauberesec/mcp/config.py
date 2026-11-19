"""Explicit MCP server configuration (v0.10).

There is no auto-discovery and no auto-connect: a server exists only when
the user lists it in the config file. Servers are untrusted by default
(`trusted=False`), which restricts them to read-only discovery until the
operator explicitly opts in.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..paths import config_dir

CONFIG_FILENAME = "mcp.json"
MAX_SERVERS = 20
MAX_ALLOWED_TOOLS = 50

# Tool names that must never be exposed: they imply unrestricted execution.
FORBIDDEN_TOOL_PATTERNS = (
    "shell",
    "exec",
    "bash",
    "sh",
    "cmd",
    "powershell",
    "eval",
    "run_command",
    "subprocess",
    "system",
    "sudo",
)


class McpConfigError(Exception):
    """The MCP configuration is missing or invalid."""


class McpServerConfig(BaseModel):
    """One explicitly configured MCP server."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]*$", max_length=64)
    command: str = Field(min_length=1, max_length=4096)
    args: tuple[str, ...] = ()
    env: dict[str, str] = Field(default_factory=dict, max_length=20)
    trusted: bool = False  # untrusted servers are discovery-only
    read_only: bool = True  # v0.10 exposes only read-only integrations
    allowed_tools: tuple[str, ...] = Field(default=(), max_length=MAX_ALLOWED_TOOLS)
    timeout_seconds: float = Field(default=20.0, gt=0, le=300)
    max_output_bytes: int = Field(default=256 * 1024, ge=1024, le=10 * 1024 * 1024)
    description: str = ""

    @field_validator("env")
    @classmethod
    def _env_key_shape(cls, v: dict[str, str]) -> dict[str, str]:
        for key, value in v.items():
            if not key or "=" in key or "\n" in value:
                raise ValueError("invalid env entry")
        return v

    @field_validator("allowed_tools")
    @classmethod
    def _allowed_tools_shaped(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for name in v:
            if not name or len(name) > 128:
                raise ValueError("invalid allowed_tools entry")
        return v

    def allows_tool(self, tool_name: str) -> bool:
        if not self.allowed_tools:
            return True  # empty allowlist = all discovered tools, subject to policy
        return tool_name in self.allowed_tools


class McpConfig(BaseModel):
    servers: tuple[McpServerConfig, ...] = Field(default=(), max_length=MAX_SERVERS)

    def get(self, name: str) -> McpServerConfig | None:
        return next((s for s in self.servers if s.name == name), None)


def config_path() -> Path:
    return config_dir() / CONFIG_FILENAME


def load_mcp_config(path: Path | None = None) -> McpConfig:
    """Load the explicit server list; an absent file means 'no servers'."""
    target = path or config_path()
    if not target.is_file():
        return McpConfig()
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise McpConfigError(f"Cannot read MCP config {target}: {exc}") from exc
    if not isinstance(data, dict):
        raise McpConfigError("MCP config must be a JSON object with a 'servers' list.")
    servers = data.get("servers", [])
    if not isinstance(servers, list):
        raise McpConfigError("'servers' must be a list.")
    return McpConfig(servers=tuple(McpServerConfig(**entry) for entry in servers))


def write_example_config(path: Path) -> None:
    """Write a documented example (no servers enabled)."""
    example = {
        "_comment": (
            "Explicit MCP servers only. Nothing here is contacted until you "
            "run an MCP command. trusted=false keeps a server discovery-only."
        ),
        "servers": [
            {
                "name": "example-fixture",
                "command": "python3",
                "args": ["-m", "mauberesec.mcp.fixture_server"],
                "trusted": False,
                "read_only": True,
                "timeout_seconds": 20,
            }
        ],
    }
    path.write_text(json.dumps(example, indent=2) + "\n", encoding="utf-8")

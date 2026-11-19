"""Normalize MCP tool schemas into internal tool contracts (v0.10).

Untrusted input: MCP descriptions/schemas come from the server. Rules:
- tool names containing shell/exec patterns are refused outright,
- only read-only tools are exposed in v0.10,
- contracts declare the modes a tool may run in (never local-lab-only
  capabilities, since MCP servers are not lab-scoped),
- descriptions are truncated and treated as untrusted text.
"""

from __future__ import annotations

from ..records import Mode
from ..tools.registry import ToolCategory, ToolContract
from .client import McpToolInfo
from .config import FORBIDDEN_TOOL_PATTERNS, McpServerConfig

MCP_TOOL_PREFIX = "mcp"


class McpToolRejected(Exception):
    """The MCP tool is not acceptable for exposure."""


def _normalized_name(server_name: str, tool_name: str) -> str:
    clean = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in tool_name.lower())
    return f"{MCP_TOOL_PREFIX}.{server_name}.{clean}"[:100]


def _looks_like_unrestricted_execution(tool_name: str, description: str) -> bool:
    haystack = f"{tool_name} {description}".lower()
    return any(pattern in haystack for pattern in FORBIDDEN_TOOL_PATTERNS)


def to_tool_contract(server: McpServerConfig, tool: McpToolInfo) -> ToolContract:
    """Convert one MCP tool into a registry contract (or raise).

    Discovery is read-only: no MCP tool may change target state in v0.10.
    """
    if not server.read_only:
        raise McpToolRejected(
            f"Server '{server.name}' is not marked read_only; write-capable MCP "
            "tools are not exposed in this milestone."
        )
    if _looks_like_unrestricted_execution(tool.name, tool.description):
        raise McpToolRejected(
            f"MCP tool '{tool.name}' from '{server.name}' looks like unrestricted "
            "execution and is never exposed."
        )
    if not server.allows_tool(tool.name):
        raise McpToolRejected(
            f"MCP tool '{tool.name}' is not in the allowlist for '{server.name}'."
        )

    return ToolContract(
        name=_normalized_name(server.name, tool.name),
        version="mcp",
        category=ToolCategory.STATIC_ANALYSIS,  # read-only information retrieval
        allowed_modes=frozenset({Mode.LOCAL_FILE, Mode.LIVE_WHITE_HAT}),
        read_only=True,
        changes_target_state=False,
        description=(f"[mcp:{server.name} v? untrusted] {tool.description[:300]}"),
    )


def exposed_tool_name(server_name: str, mcp_tool_name: str) -> str:
    return _normalized_name(server_name, mcp_tool_name)

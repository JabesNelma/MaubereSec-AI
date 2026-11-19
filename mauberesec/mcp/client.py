"""Official-SDK MCP client wrapper with timeouts and output caps (v0.10).

Uses the official Python MCP SDK (`mcp`). Every operation is bounded:
- server start/initialize/list/call run under an asyncio timeout,
- tool output is truncated to a per-server byte cap,
- outputs are treated as untrusted data (framed by callers).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any

from .config import McpServerConfig


class McpClientError(Exception):
    """The MCP interaction failed (startup, protocol, timeout)."""


class McpTimeoutError(McpClientError):
    """The MCP operation exceeded its deadline."""


class McpOutputTooLargeError(McpClientError):
    """The server returned more data than the configured cap allows."""


@dataclass(frozen=True)
class McpToolInfo:
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class McpServerInfo:
    name: str
    version: str
    protocol_version: str = ""


@dataclass(frozen=True)
class McpCallResult:
    text: str
    is_error: bool
    truncated: bool = False


def _sdk() -> tuple[Any, Any, Any]:
    """Import the official SDK lazily so the CLI works without it installed."""
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
    except ImportError as exc:  # pragma: no cover - dependency is installed in CI
        raise McpClientError(
            "The official MCP SDK is not installed. Install it with: pip install mcp"
        ) from exc
    return ClientSession, StdioServerParameters, stdio_client


def sdk_available() -> bool:
    try:
        _sdk()
        return True
    except McpClientError:
        return False


class McpClient:
    """Bounded, synchronous facade over the async SDK."""

    def __init__(self, server: McpServerConfig) -> None:
        self.server = server

    # -- internals ------------------------------------------------------------

    def _params(self) -> Any:
        _session, StdioServerParameters, _stdio = _sdk()
        return StdioServerParameters(
            command=self.server.command,
            args=list(self.server.args),
            env=dict(self.server.env) or None,
        )

    def _run(self, coro_factory: Callable[[Any], Coroutine[Any, Any, Any]], timeout: float) -> Any:
        async def runner() -> Any:
            ClientSession, _params_cls, stdio_client = _sdk()
            async with stdio_client(self._params()) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    return await coro_factory(session)

        try:
            return asyncio.run(asyncio.wait_for(runner(), timeout=timeout))
        except TimeoutError as exc:
            raise McpTimeoutError(f"MCP server '{self.server.name}' exceeded {timeout}s.") from exc
        except McpTimeoutError:
            raise
        except Exception as exc:
            raise McpClientError(
                f"MCP server '{self.server.name}' failed: {type(exc).__name__}: {exc}"
            ) from exc

    @staticmethod
    def _truncate(text: str, cap: int) -> tuple[str, bool]:
        if len(text.encode("utf-8", "replace")) <= cap:
            return text, False
        truncated = text.encode("utf-8", "replace")[:cap].decode("utf-8", "ignore")
        return truncated, True

    # -- operations --------------------------------------------------------------

    def server_info(self) -> McpServerInfo:
        async def query(session: Any) -> McpServerInfo:
            info = await session.initialize()
            return McpServerInfo(
                name=info.server_info.name,
                version=info.server_info.version,
                protocol_version=getattr(info, "protocol_version", "") or "",
            )

        result: McpServerInfo = self._run(query, self.server.timeout_seconds)
        return result

    def list_tools(self) -> list[McpToolInfo]:
        async def query(session: Any) -> list[McpToolInfo]:
            listing = await session.list_tools()
            return [
                McpToolInfo(
                    name=tool.name,
                    description=(tool.description or "")[:2000],
                    input_schema=dict(tool.input_schema or {}),
                )
                for tool in listing.tools
            ]

        result: list[McpToolInfo] = self._run(query, self.server.timeout_seconds)
        return result

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> McpCallResult:
        async def query(session: Any) -> McpCallResult:
            result = await session.call_tool(tool_name, arguments)
            parts: list[str] = []
            for block in result.content or []:
                text = getattr(block, "text", None)
                if text is not None:
                    parts.append(str(text))
            return McpCallResult(
                text="\n".join(parts),
                is_error=bool(getattr(result, "is_error", False)),
            )

        raw: McpCallResult = self._run(query, self.server.timeout_seconds)
        text, truncated = self._truncate(raw.text, self.server.max_output_bytes)
        if truncated:
            text += "\n…[truncated by mauberesec output cap]"
        return McpCallResult(text=text, is_error=raw.is_error, truncated=truncated)

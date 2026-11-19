"""MCP bridge: explicit config -> discovery -> policy-gated invocation (v0.10).

Properties:
- Nothing connects until the user asks for a specific configured server.
- Every invocation passes the deterministic policy gateway and is audited.
- Server identity/version/trust is recorded; untrusted servers are
  discovery-only (calls refused).
- Outputs are injected into the audit/report path as untrusted text, with
  injection markers detected.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..agent.injection import detect_injection_markers
from ..policy.gateway import LabRegistry, PolicyDenied, PolicyGateway
from ..records import AuditEventRecord, Mode, Scope, ScopeTarget, TargetKind
from ..storage.db import Database
from ..tools.registry import ToolRegistry
from .client import McpCallResult, McpClient, McpClientError, McpToolInfo
from .config import McpConfig, McpConfigError, McpServerConfig, load_mcp_config
from .normalize import McpToolRejected, exposed_tool_name, to_tool_contract


class McpNotConfiguredError(Exception):
    """The requested server is not in the explicit configuration."""


@dataclass
class DiscoveredServer:
    config: McpServerConfig
    server_name: str = ""
    server_version: str = ""
    protocol_version: str = ""
    tools: list[McpToolInfo] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)


class McpBridge:
    def __init__(
        self,
        db: Database,
        config: McpConfig | None = None,
        registry: ToolRegistry | None = None,
    ) -> None:
        self._db = db
        self._config = config if config is not None else load_mcp_config()
        self._registry = registry or ToolRegistry()

    # -- audit -------------------------------------------------------------------

    def _audit(self, category: str, decision: str, details: str, assessment_id: str | None) -> None:
        self._db.save_audit_event(
            AuditEventRecord(
                assessment_id=assessment_id,
                category=category,
                decision=decision,
                details=details[:1000],
            )
        )

    # -- config -------------------------------------------------------------------

    def configured_servers(self) -> list[McpServerConfig]:
        return list(self._config.servers)

    def server(self, name: str) -> McpServerConfig:
        found = self._config.get(name)
        if found is None:
            from .config import config_path

            raise McpNotConfiguredError(
                f"MCP server '{name}' is not configured. Servers are never "
                f"auto-discovered; add it explicitly to {config_path()}."
            )
        return found

    # -- discovery (read-only) ------------------------------------------------------

    def discover(self, name: str) -> DiscoveredServer:
        config = self.server(name)
        client = McpClient(config)
        info = client.server_info()
        discovered = DiscoveredServer(
            config=config,
            server_name=info.name,
            server_version=info.version,
            protocol_version=info.protocol_version,
        )
        for tool in client.list_tools():
            try:
                contract = to_tool_contract(config, tool)
            except McpToolRejected as exc:
                discovered.rejected.append(str(exc))
                self._audit("mcp_discovery", "deny", str(exc), None)
                continue
            try:
                self._registry.register(contract)
            except ValueError:
                pass  # already registered (idempotent discovery)
            discovered.tools.append(tool)
        self._audit(
            "mcp_discovery",
            "allow" if config.trusted else "info",
            f"server={info.name} v{info.version} tools={len(discovered.tools)} "
            f"rejected={len(discovered.rejected)} trusted={config.trusted}",
            None,
        )
        return discovered

    # -- invocation (policy-gated) ----------------------------------------------------

    def call_tool(
        self,
        server_name: str,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        assessment_id: str | None = None,
        mode: Mode = Mode.LOCAL_FILE,
        scope: Scope | None = None,
    ) -> McpCallResult:
        config = self.server(server_name)
        if not config.trusted:
            self._audit(
                "mcp_call",
                "deny",
                f"server '{server_name}' is untrusted; calls are refused.",
                assessment_id,
            )
            raise McpClientError(
                f"MCP server '{server_name}' is untrusted (trusted=false): discovery "
                "is allowed, invocation is not. This is deliberate."
            )

        contract_name = exposed_tool_name(server_name, tool_name)
        scope = scope or Scope(
            mode=mode,
            targets=(ScopeTarget(kind=TargetKind.REPO, value=f"mcp:{server_name}"),),
        )
        # Deterministic policy check before anything is executed.
        gateway = PolicyGateway(self._db, self._registry, _null_labs())
        from ..records import AssessmentRecord

        assessment = AssessmentRecord(mode=scope.mode, scope=scope)
        try:
            gateway.check_tool_call(assessment, contract_name, f"mcp:{server_name}")
        except PolicyDenied as exc:
            self._audit("mcp_call", "deny", str(exc), assessment_id)
            raise

        client = McpClient(config)
        try:
            result = client.call_tool(tool_name, arguments)
        except McpClientError as exc:
            self._audit("mcp_call", "error", str(exc), assessment_id)
            raise

        markers = detect_injection_markers(result.text)
        if markers:
            self._audit(
                "injection_marker",
                "info",
                f"mcp:{server_name}.{tool_name} output: {','.join(markers)}",
                assessment_id,
            )
        self._audit(
            "mcp_call",
            "allow",
            f"mcp:{server_name}.{tool_name} ok={not result.is_error} "
            f"truncated={result.truncated} bytes={len(result.text)}",
            assessment_id,
        )
        return result


def _null_labs() -> LabRegistry:
    return LabRegistry()


__all__ = [
    "McpBridge",
    "McpConfigError",
    "McpNotConfiguredError",
]

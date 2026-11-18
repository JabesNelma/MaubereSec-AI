"""Tool contract and registry.

A tool is a fixed, named adapter with declared capabilities. The agent
can only invoke tools present in the registry; the policy gateway checks
every invocation against the tool's contract before execution.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from ..records import Mode


class ToolCategory(StrEnum):
    PASSIVE_HTTP = "passive_http"
    STATIC_ANALYSIS = "static_analysis"
    DEPENDENCY_ANALYSIS = "dependency_analysis"
    APK_STATIC = "apk_static"
    LAB_RECON = "lab_recon"
    LAB_VALIDATION = "lab_validation"


class ToolContract(BaseModel):
    """Static declaration of what a tool may do and in which modes."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1, pattern=r"^[a-z0-9][a-z0-9_.-]*$")
    version: str = Field(min_length=1)
    category: ToolCategory
    allowed_modes: frozenset[Mode]
    read_only: bool = True
    changes_target_state: bool = False
    description: str = ""


class UnknownToolError(Exception):
    """The requested tool is not registered."""


class ToolRegistry:
    """In-memory registry of approved tools."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolContract] = {}

    def register(self, contract: ToolContract) -> ToolContract:
        if contract.name in self._tools:
            raise ValueError(f"Tool '{contract.name}' is already registered.")
        self._tools[contract.name] = contract
        return contract

    def get(self, name: str) -> ToolContract:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise UnknownToolError(f"Tool '{name}' is not registered.") from exc

    def names(self) -> list[str]:
        return sorted(self._tools)

    def all(self) -> list[ToolContract]:
        return [self._tools[n] for n in self.names()]


def default_registry() -> ToolRegistry:
    """Registry seeded with the v0.2 contract stubs (executors arrive later)."""
    registry = ToolRegistry()
    registry.register(
        ToolContract(
            name="passive.http_headers",
            version="0.1",
            category=ToolCategory.PASSIVE_HTTP,
            allowed_modes=frozenset({Mode.LIVE_WHITE_HAT, Mode.LOCAL_LAB}),
            description="Fetch and review HTTP/TLS security headers (passive).",
        )
    )
    registry.register(
        ToolContract(
            name="static.semgrep",
            version="0.1",
            category=ToolCategory.STATIC_ANALYSIS,
            allowed_modes=frozenset({Mode.LOCAL_FILE, Mode.LOCAL_LAB}),
            description="Semgrep adapter (restricted container; v0.5 executor).",
        )
    )
    registry.register(
        ToolContract(
            name="apk.static_review",
            version="0.1",
            category=ToolCategory.APK_STATIC,
            allowed_modes=frozenset({Mode.LOCAL_FILE, Mode.LOCAL_LAB}),
            description="APK static analysis adapter (v0.6 executor).",
        )
    )
    registry.register(
        ToolContract(
            name="lab.recon",
            version="0.1",
            category=ToolCategory.LAB_RECON,
            allowed_modes=frozenset({Mode.LOCAL_LAB}),
            description="Reconnaissance inside a registered local lab (v0.3+).",
        )
    )
    registry.register(
        ToolContract(
            name="lab.controlled_validation",
            version="0.1",
            category=ToolCategory.LAB_VALIDATION,
            allowed_modes=frozenset({Mode.LOCAL_LAB}),
            read_only=False,
            changes_target_state=True,
            description="State-changing validation; lab-only, per-run confirmation (v0.8).",
        )
    )
    return registry

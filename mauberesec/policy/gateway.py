"""Deterministic policy gateway and mode classification.

This module is the security boundary between the (untrusted) agent and
execution. Every tool call, mode request, and destination check flows
through here. Rules:

- Local Lab mode requires a *registered* lab target; a CLI flag, a
  ``localhost`` hostname, or an unregistered private IP never grants it.
- Unknown or uncertain targets fail closed to Live White-Hat
  restrictions.
- Live assessments require a valid authorization record matching the
  exact scope hash.
- State-changing tools are lab-only and require explicit confirmation.
- Every decision is persisted as an audit event.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from ..records import (
    AssessmentRecord,
    AuditEventRecord,
    AuthorizationRecord,
    Mode,
    Scope,
    TargetKind,
)
from ..storage.db import Database
from ..tools.registry import ToolContract, ToolRegistry, UnknownToolError


class PolicyDenied(Exception):
    """The requested action was denied by deterministic policy."""

    def __init__(self, reason: str, decision: PolicyDecision) -> None:
        super().__init__(reason)
        self.decision = decision


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    category: str = "policy"


class LabRegistry:
    """Registered local-lab networks/hosts (lab manager arrives in v0.3).

    Membership is by explicit registration only; nothing is inferred
    from hostnames or private address ranges.
    """

    def __init__(self) -> None:
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._hosts: set[str] = set()

    def register_network(self, cidr: str) -> None:
        net = ipaddress.ip_network(cidr, strict=False)
        self._networks.append(net)

    def register_host(self, host: str) -> None:
        self._hosts.add(host.lower())

    def is_registered(self, host: str) -> bool:
        host = host.lower()
        if host in self._hosts:
            return True
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(addr in net for net in self._networks)


# Hostnames that must never, by themselves, establish lab status.
_NON_PROOF_HOSTNAMES = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}  # noqa: S104 - denylist, not a bind


def classify_target(host: str, labs: LabRegistry) -> Mode:
    """Classify a network target deterministically.

    - Registered lab host/network -> LOCAL_LAB.
    - Anything else (including localhost, private IPs, unknown hosts)
      -> LIVE_WHITE_HAT (fail closed to stricter rules).
    """
    if host.strip().lower() in _NON_PROOF_HOSTNAMES and not labs.is_registered(host):
        return Mode.LIVE_WHITE_HAT
    if labs.is_registered(host):
        return Mode.LOCAL_LAB
    return Mode.LIVE_WHITE_HAT


def classify_file_target(path_exists_in_selection: bool) -> Mode:
    """LOCAL_FILE only for explicitly selected local paths."""
    return Mode.LOCAL_FILE if path_exists_in_selection else Mode.LIVE_WHITE_HAT


class PolicyGateway:
    """Checks and audits every proposed action for an assessment."""

    def __init__(
        self,
        db: Database,
        registry: ToolRegistry,
        labs: LabRegistry,
    ) -> None:
        self._db = db
        self._registry = registry
        self._labs = labs

    # -- audit ----------------------------------------------------------------

    def _audit(
        self,
        category: str,
        decision: PolicyDecision,
        assessment_id: str | None = None,
    ) -> None:
        self._db.save_audit_event(
            AuditEventRecord(
                assessment_id=assessment_id,
                category=category,
                decision="allow" if decision.allowed else "deny",
                details=decision.reason,
            )
        )

    # -- assessment start --------------------------------------------------------

    def authorize_assessment(
        self,
        scope: Scope,
        authorization: AuthorizationRecord | None,
    ) -> AssessmentRecord:
        """Validate mode/scope/authorization and persist the assessment."""
        if scope.mode == Mode.LIVE_WHITE_HAT:
            if authorization is None:
                decision = PolicyDecision(
                    False, "Live assessment requires an authorization record.", "authorization"
                )
                self._audit("authorization", decision)
                raise PolicyDenied(decision.reason, decision)
            if authorization.scope_sha256 != scope.sha256():
                decision = PolicyDecision(
                    False,
                    "Authorization scope hash does not match the requested scope.",
                    "authorization",
                )
                self._audit("authorization", decision)
                raise PolicyDenied(decision.reason, decision)
            if not authorization.is_valid_at():
                decision = PolicyDecision(
                    False, "Authorization record has expired.", "authorization"
                )
                self._audit("authorization", decision)
                raise PolicyDenied(decision.reason, decision)
        elif scope.mode == Mode.LOCAL_LAB:
            # Every lab target must be registered right now.
            for target in scope.targets:
                if target.kind == TargetKind.WEBSITE and not self._labs.is_registered(
                    target.value.split(":")[0]
                ):
                    decision = PolicyDecision(
                        False,
                        f"Target '{target.value}' is not a registered local lab; "
                        "failing closed to live restrictions (assessment blocked).",
                        "mode_classification",
                    )
                    self._audit("mode_classification", decision)
                    raise PolicyDenied(decision.reason, decision)

        record = AssessmentRecord(mode=scope.mode, scope=scope)
        if authorization is not None:
            record = record.model_copy(update={"authorization_reference": authorization.reference})
        self._db.save_assessment(record)
        self._audit(
            "assessment_start",
            PolicyDecision(True, f"Assessment {record.id} authorized (mode={scope.mode.value})."),
            record.id,
        )
        return record

    # -- tool calls ------------------------------------------------------------------

    def check_tool_call(
        self,
        assessment: AssessmentRecord,
        tool_name: str,
        target: str,
        confirmed_state_change: bool = False,
    ) -> ToolContract:
        """Validate a proposed tool call; raise PolicyDenied otherwise."""
        try:
            contract = self._registry.get(tool_name)
        except UnknownToolError as exc:
            decision = PolicyDecision(False, str(exc), "tool")
            self._audit("tool_call", decision, assessment.id)
            raise PolicyDenied(decision.reason, decision) from exc

        if assessment.mode not in contract.allowed_modes:
            decision = PolicyDecision(
                False,
                f"Tool '{tool_name}' is not allowed in mode {assessment.mode.value}.",
                "tool_call",
            )
            self._audit("tool_call", decision, assessment.id)
            raise PolicyDenied(decision.reason, decision)

        # Target must stay inside the scope.
        kind = (
            TargetKind.WEBSITE
            if contract.category.value.startswith(("passive", "lab"))
            else TargetKind.APK
            if contract.category.value == "apk_static"
            else TargetKind.REPO
        )
        if not assessment.scope.contains(kind, target):
            decision = PolicyDecision(
                False, f"Target '{target}' is outside the assessment scope.", "scope"
            )
            self._audit("tool_call", decision, assessment.id)
            raise PolicyDenied(decision.reason, decision)

        # State-changing tools need explicit per-run confirmation (lab only).
        if contract.changes_target_state and not confirmed_state_change:
            decision = PolicyDecision(
                False,
                f"Tool '{tool_name}' changes target state and requires explicit "
                "per-run confirmation.",
                "confirmation",
            )
            self._audit("tool_call", decision, assessment.id)
            raise PolicyDenied(decision.reason, decision)

        self._audit(
            "tool_call",
            PolicyDecision(True, f"Tool '{tool_name}' allowed on '{target}'."),
            assessment.id,
        )
        return contract

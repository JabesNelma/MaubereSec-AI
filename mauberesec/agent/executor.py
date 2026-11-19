"""Bounded agent executor (PRD AG-002..AG-007).

Every step is policy-gateway-checked before dispatch; only registered
executors run; budgets and cancellation stop the loop safely; every action
(outcome, denial, injection marker) is persisted as an audit event and the
findings collected so far are preserved as partial results.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..policy.gateway import PolicyDenied, PolicyGateway
from ..records import (
    AssessmentRecord,
    AuditEventRecord,
    FindingRecord,
    ResourceBudget,
    ToolRunRecord,
)
from ..storage.db import Database
from ..tools.registry import ToolRegistry
from .injection import detect_injection_markers
from .state import (
    AgentState,
    BudgetExhaustedError,
    CancelledError,
    RunReport,
    RunStatus,
    StepOutcome,
)


@dataclass
class StepResult:
    detail: str = ""
    findings: list[FindingRecord] = field(default_factory=list)


Executor = Callable[[AssessmentRecord, Any], StepResult]


class UnknownExecutorError(Exception):
    """No executor is wired for a registered tool."""


class ExecutorRegistry:
    def __init__(self) -> None:
        self._executors: dict[str, Executor] = {}

    def register(self, tool_name: str, executor: Executor) -> None:
        if tool_name in self._executors:
            raise ValueError(f"Executor for '{tool_name}' already registered.")
        self._executors[tool_name] = executor

    def get(self, tool_name: str) -> Executor:
        try:
            return self._executors[tool_name]
        except KeyError as exc:
            raise UnknownExecutorError(f"No executor wired for '{tool_name}'.") from exc

    def names(self) -> list[str]:
        return sorted(self._executors)


class BoundedAgent:
    def __init__(
        self,
        db: Database,
        gateway: PolicyGateway,
        registry: ToolRegistry,
        executors: ExecutorRegistry,
        budget: ResourceBudget,
        state: AgentState | None = None,
    ) -> None:
        self._db = db
        self._gateway = gateway
        self._registry = registry
        self._executors = executors
        self.state = state or AgentState(budget)

    def _audit(self, category: str, decision: str, details: str, assessment_id: str) -> None:
        self._db.save_audit_event(
            AuditEventRecord(
                assessment_id=assessment_id,
                category=category,
                decision=decision,
                details=details,
            )
        )

    def run(self, assessment: AssessmentRecord, plan: Any) -> RunReport:
        """Execute *plan* (AssessmentPlan) under all bounds."""
        self.state.start()
        report = RunReport(final_status=RunStatus.RUNNING)

        for index, step in enumerate(plan.steps):
            try:
                self.state.begin_step()
            except (CancelledError, BudgetExhaustedError) as exc:
                report.outcomes.append(
                    StepOutcome(index, step.tool_name, step.target, "skipped", str(exc))
                )
                break

            # Injection markers in plan-provided fields are audited, never run.
            markers = detect_injection_markers(f"{step.rationale} {step.target}")
            if markers:
                self._audit(
                    "injection_marker",
                    "info",
                    f"plan step {index}: {','.join(markers)}",
                    assessment.id,
                )

            try:
                self._gateway.check_tool_call(
                    assessment,
                    step.tool_name,
                    step.target,
                    confirmed_state_change=bool(step.params.get("confirm_state_change") == "true"),
                )
            except PolicyDenied as exc:
                report.outcomes.append(
                    StepOutcome(index, step.tool_name, step.target, "denied", str(exc))
                )
                continue

            try:
                executor = self._executors.get(step.tool_name)
            except UnknownExecutorError as exc:
                self._audit("tool_call", "error", str(exc), assessment.id)
                report.outcomes.append(
                    StepOutcome(index, step.tool_name, step.target, "failed", str(exc))
                )
                continue

            try:
                result = executor(assessment, step)
            except Exception as exc:
                detail = f"executor failed: {exc}"[:400]
                self._audit("tool_call", "error", detail, assessment.id)
                report.outcomes.append(
                    StepOutcome(index, step.tool_name, step.target, "failed", detail)
                )
                continue

            markers_out = detect_injection_markers(result.detail)
            if markers_out:
                self._audit(
                    "injection_marker",
                    "info",
                    f"output of {step.tool_name}: {','.join(markers_out)}",
                    assessment.id,
                )

            saved = 0
            for finding in result.findings:
                self._db.save_finding(finding.model_copy(update={"assessment_id": assessment.id}))
                saved += 1
            self._db.save_tool_run(
                ToolRunRecord(
                    assessment_id=assessment.id,
                    tool_name=step.tool_name,
                    exit_code=0,
                    redacted_summary=result.detail[:1000],
                )
            )
            self._audit(
                "tool_call",
                "allow",
                f"{step.tool_name} completed on {step.target}.",
                assessment.id,
            )
            report.outcomes.append(
                StepOutcome(index, step.tool_name, step.target, "ok", result.detail, saved)
            )
            report.total_findings += saved

        if self.state.status == RunStatus.RUNNING:
            self.state.transition(RunStatus.COMPLETED)
        report.final_status = self.state.status
        self._finish_assessment(assessment, report)
        return report

    def _finish_assessment(self, assessment: AssessmentRecord, report: RunReport) -> None:
        status_map = {
            RunStatus.COMPLETED: "completed",
            RunStatus.CANCELLED: "cancelled",
            RunStatus.BUDGET_EXHAUSTED: "failed",
            RunStatus.FAILED: "failed",
        }
        self._db.save_assessment(
            assessment.model_copy(update={"status": status_map.get(self.state.status, "failed")})
        )
        self._audit(
            "run_finish",
            "info",
            f"agent run {report.final_status.value}: "
            f"{len(report.outcomes)} outcomes, {report.total_findings} findings.",
            assessment.id,
        )

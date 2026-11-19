"""Bounded agent state machine and run statuses (PRD AG-004/AG-006)."""

from __future__ import annotations

import enum
import threading
import time
from dataclasses import dataclass, field

from ..records import ResourceBudget


class RunStatus(enum.StrEnum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    BUDGET_EXHAUSTED = "budget_exhausted"
    FAILED = "failed"


_ALLOWED_TRANSITIONS: dict[RunStatus, frozenset[RunStatus]] = {
    RunStatus.CREATED: frozenset({RunStatus.RUNNING, RunStatus.CANCELLED, RunStatus.FAILED}),
    RunStatus.RUNNING: frozenset(
        {
            RunStatus.COMPLETED,
            RunStatus.CANCELLED,
            RunStatus.BUDGET_EXHAUSTED,
            RunStatus.FAILED,
        }
    ),
    RunStatus.COMPLETED: frozenset(),
    RunStatus.CANCELLED: frozenset(),
    RunStatus.BUDGET_EXHAUSTED: frozenset(),
    RunStatus.FAILED: frozenset(),
}


class InvalidTransition(Exception):
    """Illegal state-machine transition."""


class AgentState:
    """Explicit, testable state machine with a wall-clock budget check."""

    def __init__(self, budget: ResourceBudget, started_at: float | None = None) -> None:
        self.status = RunStatus.CREATED
        self.budget = budget
        self.started_at = started_at if started_at is not None else time.monotonic()
        self.steps_used = 0
        self.cancel = threading.Event()
        self.history: list[tuple[RunStatus, RunStatus]] = []

    def transition(self, to: RunStatus) -> RunStatus:
        if to not in _ALLOWED_TRANSITIONS[self.status]:
            raise InvalidTransition(f"Cannot transition {self.status.value} -> {to.value}.")
        self.history.append((self.status, to))
        self.status = to
        return self.status

    def start(self) -> None:
        self.transition(RunStatus.RUNNING)

    def begin_step(self) -> None:
        """Call before each step; raises on budget/cancellation."""
        if self.cancel.is_set():
            self.transition(RunStatus.CANCELLED)
            raise CancelledError("Run cancelled by user.")
        elapsed = time.monotonic() - self.started_at
        if elapsed > self.budget.max_runtime_seconds:
            self.transition(RunStatus.BUDGET_EXHAUSTED)
            raise BudgetExhaustedError(
                f"Runtime budget exhausted ({self.budget.max_runtime_seconds}s)."
            )
        if self.steps_used >= self.budget.max_steps:
            self.transition(RunStatus.BUDGET_EXHAUSTED)
            raise BudgetExhaustedError(f"Step budget exhausted ({self.budget.max_steps} steps).")
        self.steps_used += 1

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started_at


class CancelledError(Exception):
    """The run was cancelled; partial results are preserved."""


class BudgetExhaustedError(Exception):
    """A run budget was exhausted; partial results are preserved."""


@dataclass
class StepOutcome:
    index: int
    tool_name: str
    target: str
    status: str  # ok|denied|failed|skipped
    detail: str = ""
    finding_count: int = 0


@dataclass
class RunReport:
    final_status: RunStatus
    outcomes: list[StepOutcome] = field(default_factory=list)
    total_findings: int = 0

    def summary(self) -> str:
        lines = [f"status: {self.final_status.value}, findings: {self.total_findings}"]
        for o in self.outcomes:
            lines.append(f"  [{o.status}] {o.tool_name} -> {o.target}: {o.detail[:120]}")
        return "\n".join(lines)

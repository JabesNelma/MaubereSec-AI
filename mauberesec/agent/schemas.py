"""Plan schemas and validation (PRD AG-001/AG-002/AG-008).

A plan is a structured proposal only. Validation enforces:
- every tool exists in the registry,
- every target is inside the assessment scope,
- every tool is allowed in the plan's mode,
- the plan fits the step budget.
The mode is copied from the scope — the model can never choose it.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, Field, field_validator

from ..records import Mode, ResourceBudget, Scope, TargetKind
from ..tools.registry import ToolCategory, ToolRegistry, UnknownToolError

MAX_GOAL_CHARS = 4000


class PlanValidationError(Exception):
    """The proposed plan violates registry/scope/budget policy."""


class PlanStep(BaseModel):
    tool_name: str = Field(min_length=1, max_length=100)
    target: str = Field(min_length=1, max_length=2048)
    params: dict[str, str] = Field(default_factory=dict, max_length=20)
    rationale: str = Field(default="", max_length=1000)

    @field_validator("tool_name")
    @classmethod
    def _clean_tool(cls, v: str) -> str:
        if any(ch.isspace() for ch in v) or any(c in v for c in (";", "|", "&")):
            raise ValueError("tool_name must be a bare identifier")
        return v

    @field_validator("params")
    @classmethod
    def _flat_params(cls, v: dict[str, str]) -> dict[str, str]:
        for key, value in v.items():
            if not key or len(key) > 100 or len(value) > 2000:
                raise ValueError("plan params out of bounds")
        return v


class AssessmentPlan(BaseModel):
    goal: str = Field(min_length=1, max_length=MAX_GOAL_CHARS)
    mode: Mode  # forced from the scope by the planner; never model-chosen
    steps: list[PlanStep] = Field(default_factory=list, max_length=100)
    created_by: str = Field(default="deterministic", max_length=100)


def _category_kind(category: ToolCategory) -> TargetKind:
    value = category.value
    if value.startswith(("passive", "lab")):
        return TargetKind.WEBSITE
    if value == "apk_static":
        return TargetKind.APK
    return TargetKind.REPO


def validate_plan(
    plan: AssessmentPlan,
    scope: Scope,
    registry: ToolRegistry,
    budget: ResourceBudget,
) -> None:
    """Raise PlanValidationError if the plan breaks any hard rule."""
    if plan.mode != scope.mode:
        raise PlanValidationError("Plan mode does not match the scope mode.")
    if len(plan.steps) > budget.max_steps:
        raise PlanValidationError(
            f"Plan has {len(plan.steps)} steps; budget allows {budget.max_steps}."
        )
    for i, step in enumerate(plan.steps):
        try:
            contract = registry.get(step.tool_name)
        except UnknownToolError as exc:
            raise PlanValidationError(f"Step {i}: {exc}") from exc
        if scope.mode not in contract.allowed_modes:
            raise PlanValidationError(
                f"Step {i}: tool '{step.tool_name}' is not allowed in mode {scope.mode.value}."
            )
        kind = _category_kind(contract.category)
        if not scope.contains(kind, step.target):
            raise PlanValidationError(
                f"Step {i}: target '{step.target}' is outside the assessment scope."
            )


def plan_to_prompt_context(plan: AssessmentPlan) -> str:
    """Compact deterministic rendering for logs/reports (no secrets inside)."""
    lines = [f"goal: {plan.goal[:200]}", f"mode: {plan.mode.value}"]
    for i, step in enumerate(plan.steps):
        lines.append(f"{i}. {step.tool_name} -> {step.target} ({step.rationale[:80]})")
    return "\n".join(lines)


def raw_plan_from_model(text: str) -> AssessmentPlan:
    """Parse a model completion into a plan; any deviation is an error."""
    cleaned = re.sub(r"```(?:json)?", "", text).strip()
    match = re.search(r"\{.*\}", cleaned, re.S)
    if not match:
        raise PlanValidationError("Model output contains no JSON object.")
    try:
        data: dict[str, Any] = json.loads(match.group())
    except json.JSONDecodeError as exc:
        raise PlanValidationError(f"Invalid plan JSON: {exc}") from exc
    steps = data.get("steps", [])
    if not isinstance(steps, list):
        raise PlanValidationError("Plan steps must be a list.")
    return AssessmentPlan(
        goal=str(data.get("goal", ""))[:MAX_GOAL_CHARS] or "model plan",
        mode=Mode.LOCAL_FILE,  # overwritten by planner from scope
        steps=[PlanStep(**s) for s in steps if isinstance(s, dict)],
        created_by="model",
    )

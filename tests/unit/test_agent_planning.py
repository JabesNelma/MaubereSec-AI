"""Unit tests: plan schemas, deterministic planner, state machine."""

import json as jsonlib
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))

from mauberesec.agent.planner import Planner, deterministic_plan
from mauberesec.agent.schemas import (
    AssessmentPlan,
    PlanStep,
    PlanValidationError,
    raw_plan_from_model,
    validate_plan,
)
from mauberesec.agent.state import (
    AgentState,
    BudgetExhaustedError,
    CancelledError,
    InvalidTransition,
    RunStatus,
)
from mauberesec.records import (
    Mode,
    ResourceBudget,
    Scope,
    ScopeTarget,
    TargetKind,
)
from mauberesec.tools.registry import default_registry

REG = default_registry()
BUDGET = ResourceBudget()


def web_scope(mode=Mode.LIVE_WHITE_HAT, value="example.com"):
    return Scope(mode=mode, targets=(ScopeTarget(kind=TargetKind.WEBSITE, value=value),))


def test_deterministic_plan_web():
    plan = deterministic_plan("check headers", web_scope())
    assert [s.tool_name for s in plan.steps] == ["passive.http_headers"]
    assert plan.mode == Mode.LIVE_WHITE_HAT


def test_deterministic_plan_repo():
    scope = Scope(
        mode=Mode.LOCAL_FILE,
        targets=(ScopeTarget(kind=TargetKind.REPO, value="/data/repo"),),
    )
    plan = deterministic_plan("audit", scope)
    assert [s.tool_name for s in plan.steps] == [
        "static.semgrep",
        "static.gitleaks",
        "static.osv_scanner",
    ]


def test_validate_plan_rejects_unknown_tool():
    plan = AssessmentPlan(
        goal="g",
        mode=Mode.LIVE_WHITE_HAT,
        steps=[PlanStep(tool_name="shell.rm", target="example.com")],
    )
    with pytest.raises(PlanValidationError, match="not registered"):
        validate_plan(plan, web_scope(), REG, BUDGET)


def test_validate_plan_rejects_out_of_scope_target():
    plan = AssessmentPlan(
        goal="g",
        mode=Mode.LIVE_WHITE_HAT,
        steps=[PlanStep(tool_name="passive.http_headers", target="evil.com")],
    )
    with pytest.raises(PlanValidationError, match="outside the assessment scope"):
        validate_plan(plan, web_scope(), REG, BUDGET)


def test_validate_plan_rejects_mode_mismatch():
    plan = AssessmentPlan(
        goal="g",
        mode=Mode.LOCAL_LAB,
        steps=[PlanStep(tool_name="passive.http_headers", target="example.com")],
    )
    with pytest.raises(PlanValidationError, match="mode does not match"):
        validate_plan(plan, web_scope(), REG, BUDGET)


def test_validate_plan_rejects_overbudget_steps():
    small = ResourceBudget(max_steps=1)
    plan = AssessmentPlan(
        goal="g",
        mode=Mode.LOCAL_FILE,
        steps=[
            PlanStep(tool_name="static.semgrep", target="/data/repo"),
            PlanStep(tool_name="static.gitleaks", target="/data/repo"),
        ],
    )
    scope = Scope(
        mode=Mode.LOCAL_FILE,
        targets=(ScopeTarget(kind=TargetKind.REPO, value="/data/repo"),),
    )
    with pytest.raises(PlanValidationError, match="budget allows 1"):
        validate_plan(plan, scope, REG, small)


def test_raw_plan_from_model_parses_fence():
    text = (
        '```json\n{"goal":"x","steps":[{"tool_name":"passive.http_headers",'
        '"target":"example.com","rationale":"r"}]}\n```'
    )
    plan = raw_plan_from_model(text)
    assert plan.steps[0].tool_name == "passive.http_headers"
    assert plan.created_by == "model"


def test_raw_plan_from_model_rejects_garbage():
    with pytest.raises(PlanValidationError):
        raw_plan_from_model("no json here at all")


def test_planner_model_proposal_invalid_falls_back_with_audit():
    class EvilProvider:
        name = "fake"

        def complete(self, prompt, max_output_tokens=0):
            from mauberesec.ai.base import CompletionResult

            return CompletionResult(
                text=jsonlib.dumps(
                    {
                        "goal": "pwn",
                        "steps": [
                            {"tool_name": "shell.rm", "target": "example.com"},
                        ],
                    }
                ),
                model="fake",
                provider="fake",
            )

        def list_models(self):
            return []

        def health_check(self):
            raise AssertionError

    audits: list[tuple[str, str]] = []
    planner = Planner(
        REG,
        BUDGET,
        EvilProvider(),
        audit_hook=lambda c, d, s: audits.append((c, d)),
    )
    plan = planner.build_plan("g", web_scope())
    # The invalid model plan (invented tool) must NOT be used.
    assert all(s.tool_name != "shell.rm" for s in plan.steps)
    assert plan.created_by == "deterministic"
    assert ("planner", "fallback") in audits


def test_planner_accepts_valid_model_plan():
    class GoodProvider:
        name = "fake"

        def complete(self, prompt, max_output_tokens=0):
            from mauberesec.ai.base import CompletionResult

            return CompletionResult(
                text=jsonlib.dumps(
                    {
                        "goal": "g",
                        "mode": "local_file",  # model tries to set mode — ignored
                        "steps": [
                            {
                                "tool_name": "static.gitleaks",
                                "target": "/data/repo",
                                "rationale": "secrets",
                            }
                        ],
                    }
                ),
                model="fake",
                provider="fake",
            )

    scope = Scope(
        mode=Mode.LOCAL_FILE,
        targets=(ScopeTarget(kind=TargetKind.REPO, value="/data/repo"),),
    )
    planner = Planner(REG, BUDGET, GoodProvider())
    plan = planner.build_plan("g", scope)
    assert plan.created_by == "model"
    assert plan.mode == Mode.LOCAL_FILE  # from scope, not the model


def test_planner_token_budget_exhaustion_falls_back():
    class ChattyProvider:
        name = "fake"

        def complete(self, prompt, max_output_tokens=0):
            from mauberesec.ai.base import CompletionResult

            return CompletionResult(text="x" * 100_000, model="f", provider="f")

    audits: list[tuple[str, str]] = []
    planner = Planner(
        REG,
        BUDGET,
        ChattyProvider(),
        max_model_tokens=10,
        audit_hook=lambda c, d, s: audits.append((c, d)),
    )
    plan = planner.build_plan("g", web_scope())
    assert plan.created_by == "deterministic"
    assert ("planner", "fallback") in audits


# --- state machine ---------------------------------------------------------------


def test_state_transitions():
    state = AgentState(BUDGET)
    state.start()
    assert state.status == RunStatus.RUNNING
    state.transition(RunStatus.COMPLETED)
    assert state.status == RunStatus.COMPLETED
    with pytest.raises(InvalidTransition):
        state.transition(RunStatus.RUNNING)


def test_state_step_budget():
    state = AgentState(ResourceBudget(max_steps=2))
    state.start()
    state.begin_step()
    state.begin_step()
    with pytest.raises(BudgetExhaustedError):
        state.begin_step()
    assert state.status == RunStatus.BUDGET_EXHAUSTED


def test_state_runtime_budget():
    state = AgentState(ResourceBudget(max_runtime_seconds=1), started_at=time.monotonic() - 5)
    state.start()
    with pytest.raises(BudgetExhaustedError, match="Runtime"):
        state.begin_step()


def test_state_cancellation():
    state = AgentState(BUDGET)
    state.start()
    state.cancel.set()
    with pytest.raises(CancelledError):
        state.begin_step()
    assert state.status == RunStatus.CANCELLED

# MaubereSec AI Progress

## Current milestone
v0.7 — Bounded agent planning and analysis

## Status
Implemented and tested (incl. real end-to-end agent run with container scanners) — awaiting owner validation and approval of v0.8

## Completed

### v0.1–v0.6 (approved & released)
- CLI/cloud foundation, policy/database foundation, Docker lab manager,
  passive live website assessment, source-code audit, APK static analysis.

### v0.7 (this milestone)
- [x] Structured planner (`mauberesec/agent/planner.py`): deterministic plan
      from the scope by default; optional cloud-model proposal (--use-ai) that
      is schema-parsed, validated against registry/scope/budget, and falls
      back to the deterministic plan with an AUDITED fallback event on any
      invalid/over-budget output. Model token budget enforced.
- [x] Plan schemas (`agent/schemas.py`): PlanStep/AssessmentPlan; the mode is
      always copied from the scope — the model cannot choose it;
      validate_plan rejects unknown tools, out-of-scope targets, mode
      mismatches, and over-budget step counts.
- [x] Bounded agent state machine (`agent/state.py`): explicit transitions
      (created/running/completed/cancelled/budget_exhausted/failed),
      step + runtime budgets, cancellation event.
- [x] Bounded executor (`agent/executor.py`): every step policy-gateway
      checked; only registered executors run (no shell anywhere);
      tool runs, findings, denials, errors, and run finish are all audited;
      partial results preserved on cancellation/budget exhaustion.
- [x] Prompt-injection defenses (`agent/injection.py`): untrusted content is
      hard-delimited for prompts; injection markers in plan fields or tool
      output are detected and audited (never executed).
- [x] Built-in executors (`agent/executors_builtin.py`) wiring v0.4-v0.6
      capabilities (passive HTTP, source scanners, APK analyzer); lab tools
      have no executor yet and fail safely.
- [x] CLI: `mauberesec agent plan` / `mauberesec agent run` with the same
      authorization rules as scan/audit (live requires auth flags).

## In progress
- None.

## Automated tests
- Total: 185 passed (+23 this milestone).
- Unit: plan validation matrix, deterministic plans, model-plan parsing
  (fenced JSON), invalid model plan -> audited fallback, valid model plan
  accepted with mode forced from scope, token budget exhaustion, state
  machine transitions/step/runtime/cancellation.
- Security: agent cannot run unregistered tools (denied + audited); cannot
  escape scope; unknown executor fails safely; injection fixtures in tool
  output are detected and audited but never executed; budget exhaustion
  stops with exactly budget many calls; cancellation preserves partial
  results.
- mypy strict (52 files) and ruff clean.

## Manual tests (Linux, this host)
- `mauberesec agent run <this repo> --goal "audit for secrets..."`:
  deterministic 3-step plan executed end-to-end with the real container
  scanners — semgrep 3 findings, gitleaks 3 findings, osv 0; status
  completed; 9+ audit events persisted.
- `mauberesec agent plan <repo>` prints the plan without executing.
- `mauberesec agent run https://example.com` without auth flags -> blocked.

## Known issues
- The planner makes a single completion per plan (no iterative replanning);
  multi-turn planning is future scope.
- lab.recon / lab.controlled_validation are registered tools without
  executors — steps fail safely until v0.8 wires lab validation.
- Injection-marker detection is heuristic (defense in depth); the primary
  defense remains schema validation + the policy gateway.

## Next permitted work
Only tasks in v0.8 — Controlled local-lab red-team validation (after owner approval).

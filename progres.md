# MaubereSec AI Progress

## Current milestone
v0.8 — Controlled local-lab red-team validation

## Status
Implemented and tested (incl. real lab-internal probes against demo-web) — awaiting owner validation and approval of v0.9

## Completed

### v0.1–v0.7 (approved & released)
- CLI/cloud foundation, policy/database foundation, Docker lab manager, passive
  live website assessment, source-code audit, APK static analysis, bounded agent.

### v0.8 (this milestone)
- [x] Lab test profiles (`mauberesec/labs/profiles.py`): `service_info`,
      `security_headers`, `common_paths` (safe, read-only) and
      `synthetic_login` (state-changing). Synthetic credentials are fixed
      constants; no real, default, or vendor credential lists exist anywhere.
- [x] Container probe (`labs/container/lab_probe.py`, stdlib-only, runs attached
      to the lab network only): GET-based recon, security-header review, common
      path exposure check, and a synthetic-credential POST probe that reports
      whether authentication is enforced. No redirects are ever auto-followed;
      every destination is validated against the lab subnet inside the
      container; request and time budgets are enforced.
- [x] Runner (`labs/runner.py`): refuses unregistered labs, verifies lab health
      before and after, resolves the service target automatically from the lab
      network (no guessing), gates state-changing checks behind explicit
      per-run confirmation (denials audited), captures evidence, and supports
      `--reset-after` to restore the lab baseline (roadmap reset requirement).
- [x] Policy integration: new public `LabManager.service_containers`; tool
      contracts `lab.recon` (read-only) and `lab.controlled_validation`
      (state-changing, requires confirmation) already enforce mode/scope.
- [x] CLI: `mauberesec lab test <name> [--base-url URL] [--confirm-state-change]
      [--reset-after]`.
- [x] Roadmap exclusions honored by construction: no malware, persistence,
      stealth, evasion, log deletion, credential theft, DoS, or escape logic
      exists in the lab tooling; tests target only registered disposable labs.

## In progress
- None.

## Automated tests
- Total: 199 passed (+14 this milestone).
- Unit: profile defaults/gating, payload contains synthetic-only credentials,
  state-changing checks excluded without confirmation, probe behaviour against a
  local fixture HTTP server (service info, headers, exposed path, auth
  enforcement reporting), out-of-lab destination blocked, request budget.
- Integration (real Docker): `lab test` safe checks end-to-end against
  demo-web over the lab network; state-change blocked without confirmation
  (audited); `--reset-after` restores the baseline and the lab stays healthy;
  unregistered lab refused.
- mypy strict (57 files) and ruff clean.

## Manual tests (Linux, this host)
- Registered demo-web, ran `lab test demo-web`: probe reached nginx inside the
  lab network (auto-discovered 10.66.7.2), reported service info + 4 missing
  security headers as findings.
- Without `--confirm-state-change`: synthetic_login skipped and the denial
  recorded in the audit trail.
- With confirmation: synthetic_login ran (synthetic credentials only) and the
  audit records "state-changing included: True".
- `--reset-after`: lab reset to baseline, reported, and still healthy.

## Known issues
- The demo-web profile has no login endpoint, so synthetic_login reports
  "absent" paths (correct behaviour); richer vulnerable-lab templates arrive
  with future milestone work.
- Evidence is stored as finding text + tool-run summaries (no raw response
  bodies retained, by design).

## Next permitted work
Only tasks in v0.9 — APK dynamic analysis in an isolated emulator (after owner approval).

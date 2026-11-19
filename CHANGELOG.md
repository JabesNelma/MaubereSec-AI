# Changelog

## 0.1.0 (2026-11-19)

Initial milestone: Python CLI and cloud model foundation.

- Typer CLI with `--help`, `--version`, `doctor`, `config show`,
  `models list`, `models test`.
- Pydantic settings; provider/model/key resolved from environment
  variables; no silent provider fallback.
- Provider-neutral model interface and OpenAI REST adapter (httpx)
  with timeout enforcement and clear credential errors.
- Structured JSON logging (structlog) with secret redaction; separate
  redaction module used before any cloud submission.
- Cloud data disclosure printed before model commands.
- Hardened Dockerfile and Compose service (non-root, read-only rootfs,
  cap_drop ALL, resource limits, no Docker socket, no host network).
- Tests (unit/integration/security), ruff, and mypy --strict gates.

## 0.2.0 (2026-11-19)

Milestone: configuration, database, and policy foundation.

- XDG-style config/data paths with cross-platform fallbacks.
- SQLite storage with versioned migrations (WAL, foreign keys); tables for
  assessments, scopes, tool_runs, findings, audit_events, lab_registrations.
- Typed record schemas: scope (hash-canonical), authorization (scope-hash
  bound with validity), modes, resource budgets (live/lab presets), findings,
  audit events (details auto-redacted).
- Tool contract and registry with per-mode permissions and state-change flags.
- Deterministic policy gateway: fail-closed target classification (registered
  labs only), authorization enforcement for live assessments, per-tool-call
  checks, and full audit-event persistence.
- 30 new tests (unit, integration, security).

## 0.3.0 (2026-11-19)

Milestone: Docker isolation and local lab manager.

- Allowlisted Docker CLI wrapper rejecting privileged mode, socket/host mounts,
  host networking, and non-allowlisted subcommands.
- Lab profiles with enforced hardening: internal bridge network per lab on a
  private /24, memory/CPU/PID limits, cap_drop ALL (+ capability allowlist),
  read-only rootfs with tmpfs, health checks, no host ports.
- Lab manager lifecycle: create, verify, teardown (label-scoped), reset, with
  partial-failure rollback.
- Persisted lab registrations feeding the policy LabRegistry; unregistration
  immediately revokes LOCAL_LAB classification.
- CLI commands: lab list/register/verify/teardown/reset.
- demo-web training template (nginx:1.27-alpine).
- 23 new tests including live-Docker integration tests.

## 0.4.0 (2026-11-19)

Milestone: passive live website assessment.

- URL normalization (http/https only; no credentials, query, fragment).
- Live destination validation rejecting private/loopback/link-local/multicast/
  reserved/unspecified addresses and cloud metadata endpoints (fail closed);
  lab destinations must resolve inside registered lab subnets.
- Passive HTTP checker: GET-only, cookie/credential-free, manual redirect
  following with per-hop revalidation, security-header and cookie-attribute
  checks, conservative budgets (requests, rate, timeout, response size,
  redirects).
- CLI `mauberesec scan` with live authorization flags bound to the scope hash.
- 34 new tests (unit/integration/security).

## 0.5.0 (2026-11-19)

Milestone: local source-code audit.

- Path canonicalization with symlink/traversal protection; bounded file
  inventory with generated/binary/oversized exclusions and secret-hint tracking.
- Containerized scanners (Semgrep, Gitleaks, OSV-Scanner) over a strictly
  read-only source mount: no network by default, cap_drop ALL,
  no-new-privileges, read-only rootfs, fixed commands/entrypoints/env only.
- Project code is never executed; dependencies are never installed.
- Secret values withheld from findings, evidence, and the database
  (gitleaks metadata + --redact only).
- Dependency manifest summaries (requirements.txt / package.json / go.mod).
- CLI `mauberesec audit` with --inventory-only; findings deduplicated and
  persisted with tool-run and audit-event records.
- 23 new tests (142 total) incl. live-Docker isolation tests.

## 0.6.0 (2026-11-19)

Milestone: APK static analysis.

- Host-side APK validation (size cap, ZIP magic, symlink rejection, SHA-256).
- Pure-python AXML parser for AndroidManifest.xml and network security configs.
- Containerized analyzer (python:3.12-alpine, network none, read-only mounts):
  dangerous permissions, exported components, debuggable, cleartext config,
  allowBackup, targetSdk review; embedded secret indicators with values
  withheld; ZIP-bomb protections (entry/size/ratio limits).
- The APK is never installed or executed; analysis is data-only inside a
  restricted container; staged through a controlled input location.
- CLI `mauberesec apk analyze` (+ --metadata-only); policy gateway supports
  APK targets; run_scanner supports extra validated read-only mounts.
- 20 new tests (162 total) incl. live-Docker analyzer tests.

## 0.7.0 (2026-11-19)

Milestone: bounded agent planning and analysis.

- Structured planner: deterministic scope-driven plans by default; optional
  cloud-model proposals that are schema-validated against the registry,
  scope, and budgets, with audited fallback and a model token budget.
- Plan schemas: mode is always inherited from the scope; steps are checked
  for registry membership, mode allowance, and scope containment.
- Bounded agent state machine and executor: policy-gateway check on every
  step, registered executors only (no shell anywhere), step/runtime budgets,
  cancellation with partial-result preservation, and full audit coverage
  (outcomes, denials, errors, injection markers, run finish).
- Prompt-injection defenses: hard-delimited untrusted framing for prompts
  and marker detection on plan fields and tool output.
- CLI `mauberesec agent plan|run` with the established authorization rules.
- 23 new tests (185 total).

## 0.8.0 (2026-11-19)

Milestone: controlled local-lab red-team validation.

- Lab test profiles with safe (read-only) and state-changing checks; synthetic
  credentials only — no real/default credential lists anywhere.
- Container probe attached to the lab network only: recon, security headers,
  common-path exposure, and a synthetic-credential authentication probe.
  No auto-followed redirects, per-request lab-subnet validation, request/time
  budgets.
- Runner: refuses unregistered labs, verifies health before/after, auto-resolves
  the service target from the lab network, requires explicit per-run
  confirmation for state-changing checks (denials audited), and restores the
  lab baseline with --reset-after.
- CLI `mauberesec lab test` with --confirm-state-change and --reset-after.
- 14 new tests (199 total) including live lab-internal integration runs.

## 0.9.0 (2026-11-19)

Milestone: APK dynamic analysis in an isolated emulator (experimental).

- Host capability detection (KVM/CPU virtualization/docker) with an explicit
  refusal path and a doctor line; isolation is never silently degraded.
- Synthetic-only fixtures with a dataset marker and tests asserting no
  realistic secret patterns exist.
- Fixed container entry script performing boot wait, dataset push, install,
  launch, and runtime capture; adb runs inside the container only.
- Per-run internal Docker network, detached emulator container with
  --device /dev/kvm, verified reset across runs, and full teardown.
- Narrow Docker API additions (run_emulator_container, exec_in,
  remove_container, image_exists) with allowlist updates.
- CLI `mauberesec apk dynamic` (experimental, --dry-run supported).
- 16 new tests (215 passed, 1 skipped) incl. stub-image orchestration tests.

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

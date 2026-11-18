# MaubereSec AI — Development Roadmap

**Document ID:** MSAI-ROADMAP-002  
**Version:** 2.0.0  
**Status:** Revised plan  
**Date:** 2026-11-19  
**Stack:** Python + Docker + Cloud AI only

---

## 1. Delivery rules

For every milestone:
1. Inspect the current repository and existing implementation.
2. Read `PRD.md`, `TECHNICAL_ARCHITECTURE.md`, `SECURITY_POLICY.md`, and `TESTING_STRATEGY.md`.
3. Confirm the current milestone and do not implement future milestones.
4. Preserve existing working features and data.
5. Add tests with every feature.
6. Run lint, type checks, unit tests, integration tests, security tests, and container checks relevant to the milestone.
7. Update `progres.md`, changelog, and docs.
8. Report changed files, test results, known limitations, and manual test steps.
9. Stop and wait for the project owner to manually validate and approve the next milestone.

Do not push to Git or deploy unless explicitly instructed.

## 2. v0.1 — Python CLI and cloud model foundation

### Scope
- Initialize Python project using `pyproject.toml`.
- Use a supported Python version and document it.
- Add Typer for CLI.
- Add Pydantic for configuration and data validation.
- Add structured logging.
- Add tests with pytest.
- Add lint/format/type-check tooling.
- Implement `--help`, `--version`, `doctor`.
- Define provider-neutral model interface.
- Integrate one cloud AI provider.
- Add provider/model selection from environment variables and config.
- Add `models list` and `models test`.
- Add explicit cloud data disclosure.
- Add secret redaction.

### Docker
- Add Dockerfile for the CLI runtime.
- Add Compose file for development.
- Run as non-root.
- Use read-only filesystem where practical.
- Do not mount Docker socket.
- Do not include scanners or agent tool execution yet.

### Out of scope
- Ollama/local models.
- Autonomous tool execution.
- Website scanning.
- APK analysis.
- MCP tool execution.
- Active testing.

### Acceptance
- CLI works in the supported Linux environment and container.
- Cloud provider health test succeeds with valid credentials.
- Missing/invalid credentials produce clear errors.
- No silent provider fallback.
- Cloud disclosure is visible.
- API keys never appear in logs.
- Tests, lint, type checks, and container build pass.

## 3. v0.2 — Configuration, database, and policy foundation

### Scope
- XDG-style config/data paths with cross-platform fallbacks.
- SQLite persistence and migrations.
- Assessment, tool-run, finding, and audit-event records.
- Authorization record format.
- Scope schema.
- Mode classification: Local Lab vs Live White-Hat.
- Resource budget definitions.
- Tool contract and registry interfaces.
- Deterministic policy gateway.

### Acceptance
- Missing authorization blocks live assessment.
- Local Lab mode cannot be enabled from a CLI flag alone.
- Unknown target classification fails closed to Live restrictions.
- Audit events are persisted.
- Secret redaction tests pass.

## 4. v0.3 — Docker isolation and local lab manager

### Scope
- Docker Compose lab templates for intentionally vulnerable training targets.
- Dedicated bridge network for each lab.
- Lab registration metadata.
- Lab verification command.
- Container health checks.
- CPU, memory, PID, and runtime limits.
- Non-root containers.
- No privileged mode by default.
- No Docker socket inside agent/scanner containers.
- Explicit output and fixture volumes.
- Lab teardown and reset workflow.

### Acceptance
- Agent can only recognize registered labs.
- Scanner containers cannot access unrelated host services by default.
- No privileged container is required for baseline workflows.
- Lab teardown removes only resources created by that lab profile.
- Host paths and Docker socket are not exposed to scanners.
- Platform-specific limitations are reported by `doctor`.

## 5. v0.4 — Passive live website assessment

### Scope
- Live authorization and exact scope.
- URL normalization.
- DNS and IP validation.
- Redirect revalidation.
- Passive HTTP/TLS metadata.
- Security headers and cookie attribute checks.
- Conservative request and response limits.
- Evidence normalization.

### Acceptance
- Live assessment cannot run without authorization.
- Private, loopback, link-local, multicast, reserved, and metadata destinations are rejected for live targets by default.
- Redirects cannot escape scope.
- Passive checks do not modify target state.
- Rate and timeout budgets are enforced.

## 6. v0.5 — Local source-code audit

### Scope
- Repository path selection and canonicalization.
- Symlink and traversal protection.
- File inventory and exclusions.
- Semgrep adapter in a restricted container.
- Gitleaks adapter with secret redaction.
- OSV-Scanner adapter.
- Dependency manifest analysis.
- Finding normalization and deduplication.

### Acceptance
- Project code is not executed.
- Project dependencies are not installed automatically.
- Scanner containers have read-only source mounts.
- Secrets are not sent to cloud models.
- Findings include reproducible file/line evidence where available.

## 7. v0.6 — APK static analysis

### Scope
- APK path and file validation.
- SHA-256 and metadata extraction.
- Android manifest parsing.
- Permission and exported component review.
- Network security configuration review.
- Cleartext traffic configuration checks.
- Embedded secret indicator checks with safe redaction.
- Static code/decompilation analysis using approved tools in restricted containers.
- Report evidence mapping to APK artifacts.

### Acceptance
- APK is never installed or executed on the host.
- APK processing occurs in a restricted container.
- File size and decompression limits prevent archive bombs.
- Secret values are redacted.
- Findings contain artifact evidence and confidence.
- Malformed APKs fail safely.

## 8. v0.7 — Bounded agent planning and analysis

### Scope
- Planner that creates structured assessment plans.
- Bounded agent state machine.
- Tool proposal interface.
- Deterministic policy gateway for every tool call.
- Maximum steps, calls, runtime, token/cost, and output budgets.
- Evidence-aware analysis.
- Safe cancellation and partial result support.
- Prompt injection defenses for web, code, APK, scanner, and tool output.

### Acceptance
- Agent cannot invent or call unregistered tools.
- Agent cannot change scope or mode.
- Prompt injection fixtures do not override policy.
- Budget exhaustion stops the run.
- Every action is auditable.
- No arbitrary shell command is generated or executed.

## 9. v0.8 — Controlled local-lab red-team validation

### Scope
This milestone adds deeper attacker-style validation only for verified, disposable local labs.

- Lab-specific test profiles.
- Reconnaissance and service mapping within the lab.
- Safe validation of common application weaknesses.
- Controlled proof-of-concept checks using synthetic accounts/data.
- Resettable test fixtures and snapshots.
- Explicit confirmation for any state-changing lab test.
- Evidence capture and cleanup verification.

### Explicit exclusions
- Malware, persistence, stealth, evasion, log deletion.
- Credential theft or exfiltration.
- Denial-of-service and resource exhaustion.
- Host escape or container escape attempts.
- Tests against public IPs or unregistered hosts.
- Destruction of real user data.

### Acceptance
- Tests run only against a registered disposable lab.
- Out-of-bound destinations are blocked.
- State-changing tests require explicit per-run confirmation.
- Synthetic data is used.
- Lab reset restores expected baseline.
- No host escape or destructive host operation is included.

## 10. v0.9 — APK dynamic analysis in isolated emulator

### Scope
- Evaluate emulator architecture and supported host matrix.
- Add disposable Android emulator or dedicated test-device integration.
- Use synthetic accounts and data.
- Isolate emulator networking to the lab.
- Capture runtime observations and logs.
- Reset snapshots between runs.
- Keep dynamic analysis optional and clearly marked experimental until platform tests pass.

### Platform note
Docker alone does not provide identical Android hardware virtualization on Linux, macOS, and Windows. The emulator may need to run on the host or in a dedicated VM, with Docker coordinating the workflow. `doctor` must detect missing virtualization support and explain it.

### Acceptance
- APK runs only in the disposable emulator/test device.
- No personal device is used by default.
- Network egress is restricted to the registered lab.
- Synthetic data only.
- Emulator reset is verified.
- Unsupported host platforms fail clearly rather than silently degrading isolation.

## 11. v0.10 — MCP integrations

### Scope
- Add official Python MCP client SDK after checking current official documentation.
- Explicit MCP server configuration.
- Read-only tool discovery.
- Normalize MCP schemas to internal tool contracts.
- Apply policy gateway to every MCP invocation.
- Server identity, version, and trust metadata.
- Local fixture MCP server for tests.
- Add approved scanner MCP integrations selectively.

### Acceptance
- No auto-connect to unknown MCP servers.
- MCP tool descriptions and outputs are treated as untrusted.
- No unrestricted shell MCP server is exposed.
- Every call is policy checked and audited.
- Timeouts and output caps apply.

## 12. v0.11 — Findings verification and reports

### Scope
- Finding schema and versioning.
- Severity and confidence separation.
- Evidence correlation and deduplication.
- Verification status.
- Markdown and JSON reports.
- Assessment history and inspection.
- Redaction and partial reports.

### Acceptance
- No LLM-only claim can become confirmed.
- Each finding includes evidence and remediation.
- Reports include scope, mode, tools, limitations, and untested areas.
- Reports contain no secrets.
- JSON validates against schema.

## 13. v1.0 — Stable release

### Scope
- Full regression test suite.
- Threat model review.
- Container image and dependency review.
- Cross-platform Docker verification.
- Installation and upgrade docs.
- CLI usability improvements.
- Release notes and known limitations.
- Security review of policy boundaries.

### Acceptance
- All v1.0 PRD requirements are met.
- No unresolved critical/high product security defects.
- All release gates pass.
- Linux, macOS, and Windows/WSL2 support statements match actual test evidence.
- Manual acceptance approved by project owner.

---

## 14. Progress tracking file

Create and maintain `progres.md`:

```md
# MaubereSec AI Progress

## Current milestone
v0.1 — Python CLI and cloud model foundation

## Status
Not started

## Completed
- [ ] ...

## In progress
- [ ] ...

## Automated tests
- Unit:
- Integration:
- Security:
- Docker build:
- Type checks:
- Lint:

## Manual tests
- Linux:
- macOS:
- Windows/WSL2:

## Known issues
- None recorded.

## Next permitted work
Only tasks in the current milestone.
```

## 15. Change control

Any change to programming language, AI inference model strategy, operating modes, Docker isolation, scope policy, or milestone criteria must be documented before implementation. The coding agent must not silently change the plan.

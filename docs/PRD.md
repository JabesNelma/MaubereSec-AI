# MaubereSec AI — Product Requirements Document

**Document ID:** MSAI-PRD-002  
**Version:** 2.0.0  
**Status:** Revised product baseline  
**Date:** 2026-11-19  
**Core stack:** Python + Docker  
**AI inference:** Cloud providers only (initial release)  
**Primary interface:** Terminal CLI

---

## 1. Product summary

MaubereSec AI is a terminal-first AI security assessment agent for developers, application owners, and defensive security researchers. It can inspect authorized web applications, local source-code repositories, and Android APK files. It combines a cloud-hosted AI model with established security tools, isolated Docker environments, evidence collection, and structured reporting.

The product has two distinct operating modes:

1. **Local Lab Red-Team Mode:** For targets running inside a user-controlled, isolated local lab, such as intentionally vulnerable applications, localhost services, local repositories, and test APKs. This mode can perform deeper adversarial security validation and controlled exploit simulation within strict containment.
2. **Live White-Hat Mode:** For deployed websites and systems. This mode is limited to explicitly authorized, scoped, low-impact security assessment. It must not attempt destructive actions, persistence, data theft, service disruption, or stealth.

The key product rule is that the target's actual environment and verified network destination determine the allowed mode. A hostname that looks like `localhost` is not sufficient proof that a target is safe. Every request and tool execution must be checked by deterministic policy code.

MaubereSec AI must never be an unrestricted autonomous hacking terminal. The AI proposes plans; application code authorizes, constrains, and records every action.

## 2. Product vision

Build a reliable AI security engineer that can help users understand how an attacker might compromise an application in a controlled local lab, then help them find and fix weaknesses in real deployed systems without damaging them.

## 3. Product goals

- Build a cross-platform terminal CLI using Python.
- Use Docker to package scanners and repeatable tool environments.
- Use cloud AI providers only in the initial product.
- Allow the user to select/configure a cloud provider and model from terminal configuration or environment variables.
- Audit local source-code repositories.
- Analyze Android APK files using static analysis first, with isolated dynamic analysis added later.
- Assess websites under explicit authorization and scope.
- Provide deeper, controlled red-team validation only inside a verified local lab.
- Generate evidence-backed Markdown and JSON reports.
- Keep local assessment history and logs.
- Make scope, authorization, network boundaries, and execution budgets deterministic and testable.

## 4. Non-goals

MaubereSec AI will not:
- Attack third-party systems without explicit authorization.
- Perform denial-of-service, stress testing, or destructive availability testing.
- Steal credentials, tokens, private data, or session cookies.
- Exfiltrate data.
- Install persistence, backdoors, malware, or rootkits.
- Evade detection, hide activity, erase logs, or bypass monitoring.
- Perform phishing, social engineering, or credential harvesting.
- Run unbounded brute force or password spraying.
- Automatically modify or delete production data.
- Treat an LLM response or a `localhost` string as authorization.
- Execute arbitrary model-generated shell commands.
- Escape Docker or weaken host security controls.

## 5. Terminology and operating modes

### 5.1 Local Lab Red-Team Mode

Purpose: emulate realistic attacker reasoning against a deliberately isolated target to discover and safely demonstrate weaknesses.

Eligible targets:
- A Docker Compose lab created or explicitly selected by the user.
- A local test application whose process and destination are verified as local.
- A dedicated test VM or emulator network with an explicit lab profile.
- A local source repository selected by the user.
- An APK explicitly supplied for analysis.

Permitted capabilities, subject to a specific tool profile:
- Reconnaissance and service inventory inside the lab.
- Static analysis and dependency analysis.
- Authentication and authorization logic review.
- Controlled proof-of-concept validation against synthetic accounts and synthetic data.
- Safe checks for common injection, access-control, configuration, and input-validation weaknesses.
- APK static inspection, manifest review, permission review, exported component review, insecure storage/configuration checks, and code analysis.
- Dynamic APK testing only in a disposable emulator/device environment with synthetic accounts and data, introduced in a later milestone.

Containment requirements:
- Lab targets must be explicitly registered.
- Docker lab services must use a dedicated network.
- Scanner containers must not receive host networking by default.
- No Docker socket mount into the agent or scanner container.
- No privileged containers by default.
- No host filesystem mount except the selected read-only source directory and dedicated output directory.
- No access to host credentials, browser profiles, SSH keys, cloud metadata endpoints, or unrelated local services.
- Synthetic test data only.
- Snapshot/recreate lab before destructive-state simulations.
- Any state-changing validation must be explicitly listed in the lab profile and use disposable fixtures.
- The agent must stop if a target resolves or routes outside the registered lab boundary.

“Act like an attacker” means threat-model, enumerate, test, and validate weaknesses with controlled evidence. It does not mean destroying user data, deploying malware, stealing secrets, or escaping containment.

### 5.2 Live White-Hat Mode

Purpose: assess a deployed system without disrupting service or accessing data beyond what is necessary to validate a finding.

Required:
- Written authorization record or equivalent user-supplied authorization reference.
- Exact domain/IP and permitted subdomain scope.
- Allowed ports, paths, methods, and test categories.
- Assessment window and contact/escalation details where applicable.
- Conservative rate and concurrency limits.
- Explicit confirmation before active checks.

Allowed:
- Passive HTTP/TLS/security-header review.
- Safe technology and asset inventory.
- Low-impact, non-destructive checks.
- Source-code and dependency review when repository access is authorized.
- Safe verification that does not modify data or access unrelated user information.

Prohibited:
- Destructive payloads or destructive state changes.
- Denial-of-service or stress testing.
- Credential theft, brute force, password spraying, or session hijacking.
- Data exfiltration or bulk data access.
- Persistence, malware, stealth, log tampering, or evasion.
- Testing outside the written scope.
- Any test that may materially degrade availability or integrity.

### 5.3 Mode selection and enforcement

- User chooses a mode, but the policy engine verifies whether the target qualifies.
- Local Lab mode is not granted based only on `localhost`, `127.0.0.1`, a `.local` name, or a user prompt.
- The application verifies DNS results, connection destinations, Docker network membership, registered lab identity, and redirect destinations.
- A public IP target is always treated as live unless it belongs to a separately verified private lab network.
- If classification is uncertain, fail closed and use Live White-Hat restrictions.
- The model cannot change the mode, scope, or policy.
- Mode restrictions apply to built-in tools and all MCP tools equally.

## 6. Target types

### 6.1 Websites and APIs
- Local Docker lab targets.
- Authorized live websites and APIs.
- Local development servers.

### 6.2 Source-code repositories
- User-selected local repository paths.
- Authorized repository exports or checkouts.
- No execution of project code by default.

### 6.3 Android APKs
- APK files supplied by the user or located inside a user-selected folder.
- Static analysis is the initial supported workflow.
- Dynamic analysis is a later feature requiring a disposable Android emulator/device.
- APK analysis must not install the APK onto the user's personal device.
- APKs and extracted files are untrusted input and must be processed in a restricted container.

## 7. Target users

- Full-stack and mobile developers.
- Website and application owners.
- Defensive security learners.
- Small development teams.
- Authorized security testers.

The CLI should explain risk and findings in clear language while preserving technical evidence.

## 8. Platform support

### Host platforms
- Linux: primary and most complete support.
- macOS: supported through Docker Desktop, subject to tool compatibility.
- Windows: supported through Docker Desktop with WSL2.
- Dynamic Android emulator testing may require additional host virtualization support and may not be equally available on every platform.

Docker improves reproducibility and packages tool dependencies. It does not make every scanner, kernel feature, emulator, or hardware virtualization feature identical across operating systems. The CLI must run `doctor` and report platform-specific limitations.

## 9. Functional requirements

Priority:
- **P0:** v0.1 foundation.
- **P1:** required for v1.0.
- **P2:** later enhancement.

### 9.1 CLI and configuration

| ID | Priority | Requirement |
|---|---|---|
| CLI-001 | P0 | Provide `mauberesec --help` and `--version`. |
| CLI-002 | P0 | Provide `doctor`, `config`, and `models` commands. |
| CLI-003 | P0 | Read cloud provider/model configuration from environment variables and config file. |
| CLI-004 | P0 | Keep API secrets out of config examples, logs, and reports. |
| CLI-005 | P0 | Clearly disclose that prompts/context are sent to the selected cloud provider. |
| CLI-006 | P1 | Provide `lab`, `audit`, `scan`, `apk`, `history`, and `report` commands. |
| CLI-007 | P1 | Support Ctrl+C cancellation and useful exit codes. |

### 9.2 Cloud AI

| ID | Priority | Requirement |
|---|---|---|
| AI-001 | P0 | Implement a provider-neutral Python interface. |
| AI-002 | P0 | Support one cloud provider in v0.1. |
| AI-003 | P0 | Allow provider/model selection from terminal environment variables. |
| AI-004 | P0 | Validate credentials and provider connectivity. |
| AI-005 | P0 | Never silently switch providers or send data to another provider. |
| AI-006 | P1 | Add additional cloud providers behind the same interface. |
| AI-007 | P1 | Validate structured model output with typed schemas. |
| AI-008 | P1 | Enforce token, cost, timeout, and retry budgets where supported. |

Ollama and local model execution are explicitly out of scope for this product baseline. They may be reconsidered only through a documented product change.

### 9.3 Agent orchestration

| ID | Priority | Requirement |
|---|---|---|
| AG-001 | P1 | Produce a bounded plan from a user request and registered scope. |
| AG-002 | P1 | Select only tools in the approved tool registry. |
| AG-003 | P1 | Pass every proposed tool call through deterministic policy code. |
| AG-004 | P1 | Enforce step, time, token, request, concurrency, and output budgets. |
| AG-005 | P1 | Treat websites, APK contents, repository files, scanner output, and MCP responses as untrusted data. |
| AG-006 | P1 | Stop safely on policy denial, timeout, cancellation, or budget exhaustion. |
| AG-007 | P1 | Preserve assessment state and evidence. |
| AG-008 | P1 | Never allow the model to modify authorization or scope. |

### 9.4 Docker execution environment

| ID | Priority | Requirement |
|---|---|---|
| DOC-001 | P0 | Provide Docker Compose configuration for development and approved tool services. |
| DOC-002 | P0 | Provide least-privilege container defaults. |
| DOC-003 | P0 | Use dedicated networks for local lab targets. |
| DOC-004 | P0 | Do not mount Docker socket into agent/scanner containers. |
| DOC-005 | P0 | Do not use privileged mode by default. |
| DOC-006 | P1 | Pin image versions or digests for release builds. |
| DOC-007 | P1 | Provide health checks, resource limits, and clean teardown. |
| DOC-008 | P1 | Document host-specific requirements and limitations. |

### 9.5 Website assessment

| ID | Priority | Requirement |
|---|---|---|
| WEB-001 | P1 | Require explicit authorization and scope for live targets. |
| WEB-002 | P1 | Require registered lab identity for Local Lab mode. |
| WEB-003 | P1 | Validate DNS, IP, redirects, ports, and scope before requests. |
| WEB-004 | P1 | Start with passive checks and safe low-impact validation. |
| WEB-005 | P1 | Enforce separate local-lab and live tool profiles. |
| WEB-006 | P1 | Record evidence, timestamps, tool versions, and scope decisions. |
| WEB-007 | P2 | Add controlled local-lab exploit simulation using synthetic data and resettable fixtures. |
| WEB-008 | P2 | Add selected DAST/scanner integrations behind policy adapters. |

### 9.6 Source-code audit

| ID | Priority | Requirement |
|---|---|---|
| CODE-001 | P1 | Require user-selected repository root. |
| CODE-002 | P1 | Prevent traversal and symlink escape. |
| CODE-003 | P1 | Exclude secrets, binaries, generated files, and oversized files from model context by default. |
| CODE-004 | P1 | Run approved static-analysis tools in restricted containers. |
| CODE-005 | P1 | Do not execute project scripts or install project dependencies by default. |
| CODE-006 | P1 | Include dependency advisory checks. |
| CODE-007 | P1 | Include file and line evidence where available. |

### 9.7 APK analysis

| ID | Priority | Requirement |
|---|---|---|
| APK-001 | P1 | Accept a local APK path and verify file type/size. |
| APK-002 | P1 | Compute SHA-256 and record APK metadata. |
| APK-003 | P1 | Perform static manifest, permission, component, configuration, and code analysis. |
| APK-004 | P1 | Run APK tools in restricted Docker containers. |
| APK-005 | P1 | Never install or execute the APK on the host machine. |
| APK-006 | P1 | Report findings with file/artifact evidence and confidence. |
| APK-007 | P2 | Add dynamic analysis using a disposable Android emulator/device in an isolated lab. |
| APK-008 | P2 | Use synthetic accounts/data and reset emulator snapshots between runs. |

### 9.8 Findings and reports

| ID | Priority | Requirement |
|---|---|---|
| REP-001 | P1 | Normalize findings into a versioned schema. |
| REP-002 | P1 | Separate severity from confidence. |
| REP-003 | P1 | Support confirmed, likely, needs-review, false-positive, and not-reproducible statuses. |
| REP-004 | P1 | Include evidence, impact, remediation, and verification status. |
| REP-005 | P1 | Export Markdown and JSON. |
| REP-006 | P1 | Include scope, mode, tools, limitations, and untested areas. |
| REP-007 | P1 | Never mark a vulnerability confirmed solely because an LLM claims it. |

## 10. Planned CLI interface

```bash
mauberesec --help
mauberesec --version
mauberesec doctor

mauberesec config show
mauberesec models list
mauberesec models test

mauberesec lab list
mauberesec lab register
mauberesec lab verify

mauberesec audit ./my-project
mauberesec scan https://authorized.example --mode live
mauberesec scan http://127.0.0.1:8080 --mode lab
mauberesec apk analyze ./application.apk

mauberesec history
mauberesec report <assessment-id>
mauberesec assessment show <assessment-id>
mauberesec assessment cancel <assessment-id>
```

The `--mode lab` flag is a request, not proof. The application must verify the registered lab boundary before enabling the local-lab profile.

## 11. Non-functional requirements

### Security
- Least privilege and container isolation.
- No unrestricted shell.
- No Docker socket mount.
- Explicit authorization and scope.
- Destination validation and redirect revalidation.
- Secret redaction.
- No silent cloud provider fallback.
- Untrusted content isolation.
- Audit log for tool calls and policy decisions.

### Reliability
- Graceful cancellation.
- Bounded retries.
- Persistent assessment state.
- Clear error categories.
- Partial reports on safe termination.

### Performance
- Async I/O for independent checks.
- Conservative concurrency.
- Truncated and filtered model context.
- Configurable resource budgets.

### Maintainability
- Python type hints.
- Pydantic schemas.
- Modular provider and tool adapters.
- Pinned dependencies.
- Automated tests.
- Versioned documentation.

## 12. Privacy and cloud data handling

Because the initial product uses cloud AI only:
- Display a clear notice before the first model request.
- Explain which data categories may be sent: user prompt, selected code excerpts, sanitized scanner output, and finding summaries.
- Do not send complete repositories or complete APK contents by default.
- Redact secrets before model submission.
- Provide a `--no-ai` mode for deterministic scanner-only workflows where practical.
- Never silently use a different provider.
- Record provider/model IDs, not credentials.
- Document provider retention and data controls without making unsupported promises.

## 13. v0.1 acceptance criteria

v0.1 is complete only when:
1. Python CLI installs and runs on the primary Linux development environment.
2. Docker Compose starts the development services successfully.
3. `--help`, `--version`, and `doctor` work.
4. Cloud provider and model are configurable from terminal.
5. Provider connectivity and invalid credentials are handled clearly.
6. Cloud data disclosure is shown.
7. No Ollama/local model code path is included.
8. No scanner execution or autonomous tool loop is enabled yet.
9. API keys are absent from logs and reports.
10. Unit tests, lint, type checks, and build/package checks pass.
11. Documentation and manual test records are complete.

## 14. Product release principle

Implement one milestone at a time. The AI coding agent must inspect the existing repository, preserve working code, implement only the current roadmap milestone, test it, update `progres.md`, and wait for owner approval before advancing.

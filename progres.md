# MaubereSec AI Progress

## Current milestone
v1.0 — Stable release

## Status
All automated release gates pass; awaiting project-owner manual acceptance (the last v1.0 criterion).

## Completed milestones (v0.1 → v1.0, all released)

| Version | Milestone | Tag |
|---|---|---|
| v0.1 | Python CLI + cloud model foundation | v0.3.0 (consolidated) |
| v0.2 | Configuration, database, policy foundation | v0.3.0 (consolidated) |
| v0.3 | Docker isolation + local lab manager | v0.3.0 |
| v0.4 | Passive live website assessment | v0.4.0 |
| v0.5 | Local source-code audit | v0.5.0 |
| v0.6 | APK static analysis | v0.6.0 |
| v0.7 | Bounded agent planning/analysis | v0.7.0 |
| v0.8 | Controlled local-lab red-team validation | v0.8.0 |
| v0.9 | APK dynamic analysis (experimental) | v0.9.0 |
| v0.10 | MCP integrations | v0.10.0 |
| v0.11 | Findings verification + reports | v0.11.0 |
| v1.0 | Stable release | v1.0.0 |

## v1.0 deliverables

- [x] Full regression suite: **273 passed, 1 skipped** (unit, security,
      integration incl. real Docker: scanner isolation, lab lifecycle, lab
      validation, emulator orchestration, MCP fixture server).
- [x] Threat model review → `docs/THREAT_MODEL.md` (assets, trust boundaries,
      adversaries, attack paths with controls + test references, residual
      risks, non-goals).
- [x] Security review of policy boundaries → `docs/SECURITY_REVIEW.md`
      (ten boundaries, each with enforcing module + tests; findings SR-1..SR-4
      resolved/accepted; **no unresolved critical or high defects**).
- [x] Container image and dependency review → `docs/DEPENDENCIES.md`
      (pinned scanners, image inventory, review checklist) plus a hardened
      container run inside the release gate.
- [x] Cross-platform Docker verification → `docs/SUPPORT_MATRIX.md`
      (evidence-based: Linux verified; macOS/Windows/WSL2 explicitly
      "Not tested", with instructions to extend the matrix).
- [x] Installation and upgrade docs → `docs/INSTALL.md` (requirements, install,
      config paths, verification, upgrade/migration, uninstall, troubleshooting).
- [x] CLI usability improvements: `doctor --json`, `history --json`,
      `assessment list` alias, friendlier empty states, documented exit codes
      (`docs/CLI.md`), consistent cancellation handling.
- [x] Release notes and known limitations (this file + release notes).
- [x] Reproducible release gate → `scripts/release_check.sh` (lint, types,
      tests, CLI smoke, container build, hardened run, compose syntax).

## v1.0 acceptance checklist (against PRD)

### CLI and configuration (PRD 9.1)
| ID | Requirement | Status | Evidence |
|---|---|---|---|
| CLI-001 | `--help` / `--version` | ✅ | `tests/unit/test_release_v1.py` |
| CLI-002 | `doctor`, `config`, `models` | ✅ | release-gate test asserts full command list |
| CLI-003 | Env + config file settings | ✅ | `tests/unit/test_settings.py` |
| CLI-004 | Secrets never in config output/logs/reports | ✅ | redaction tests (logs, reports, CLI) |
| CLI-005 | Cloud disclosure | ✅ | `tests/security/test_cli_security.py` |
| CLI-006 | `lab`, `audit`, `scan`, `apk`, `history`, `report` | ✅ | help-listing test |
| CLI-007 | Ctrl+C cancellation + useful exit codes | ✅ | agent/lab cancellation tests; exit codes documented |

### Cloud AI (PRD 9.2)
| AI-001 | Provider-neutral interface | ✅ | `mauberesec/ai/base.py` |
| AI-002/003 | One provider, env selection | ✅ | `test_settings.py`, `test_openai_provider.py` |
| AI-004 | Credential/connectivity validation | ✅ | `models test` mocked tests |
| AI-005 | No silent provider fallback | ✅ | `test_settings.py`, CLI security test |
| AI-007/008 | Typed output, budgets | ✅ | plan schemas; `Planner` token budget |

### Agent (PRD 9.3)
| AG-001..AG-008 | Bounded plan, registry-only tools, gateway per call, budgets, untrusted content, safe stop, evidence preservation, immutable scope | ✅ | `test_agent_planning.py`, `test_agent_security.py` |

### Docker (PRD 9.4)
| DOC-001..008 | Compose config, least privilege, dedicated networks, no socket, no privileged, pinned images, limits/health, documented platform limits | ✅ | `test_docker_client.py`, integration tests, `docs/DEPENDENCIES.md` |
| (note) | `docker compose` plugin absent on this host; compose file validated as YAML and used as documentation | ⚠️ | doctor reports it |

### Website / source / APK / reports (PRD 9.5–9.8)
| WEB-001..006 | Authorization+scope, lab identity, DNS/redirect validation, passive-only, separate profiles, evidence recorded | ✅ | `test_policy_gateway.py`, `test_urlcheck.py`, `test_passive_checker.py` |
| CODE-001..007 | Path safety, traversal defence, exclusions, containerized tools, no execution/install, advisories, file:line evidence | ✅ | `test_pathcheck_inventory.py`, `test_scanner_parsers.py`, scanner isolation tests |
| APK-001..006 | Path/file validation, SHA-256, manifest/permission/component review, restricted containers, never executed, artifact evidence | ✅ | `test_apk_analysis.py`, `test_apk_security.py`, `test_apk_container.py` |
| REP-001..007 | Versioned schema, severity≠confidence, statuses, evidence+remediation, MD+JSON, scope/mode/tools/limits, LLM cannot confirm | ✅ | `test_findings_reports.py` |
| APK-007/008 (P2) | Dynamic analysis + synthetic data | ✅ experimental | `test_dynamic_analysis.py`, emulator orchestration tests |

### Release gates (roadmap §13)
| Criterion | Status |
|---|---|
| All v1.0 PRD requirements met | ✅ (table above; one environmental caveat noted) |
| No unresolved critical/high product security defects | ✅ `docs/SECURITY_REVIEW.md` |
| All release gates pass | ✅ `scripts/release_check.sh` → PASS |
| Platform statements match actual test evidence | ✅ `docs/SUPPORT_MATRIX.md` |
| Manual acceptance by project owner | ⏳ pending owner |

## Known limitations (v1.0)

1. macOS / Windows-WSL2 support is unverified; the matrix says so explicitly.
2. `docker compose` plugin is not installed on the development host; the compose
   file is validated syntactically and used as documentation, while all
   container work runs through the allowlisted Docker CLI wrapper.
3. APK dynamic analysis is experimental and requires KVM; the real emulator
   image is opt-in (multi-GB), so orchestration is verified with a stub image.
4. Verification statuses require an explicit reproduction/refutation call; there
   is no automatic re-execution harness yet.
5. Finding evidence items are free-form observations (typed per-tool evidence is
   future work).
6. Release builds should pin container image digests (tracked in
   `docs/DEPENDENCIES.md`).

## Next permitted work
v1.0 is the final planned milestone. Further work requires a documented plan
change per ROADMAP.md §15 (change control).

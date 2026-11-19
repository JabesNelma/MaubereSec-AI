# MaubereSec AI — Policy Boundary Security Review (v1.0)

Each boundary below is enforced by deterministic code, not by the model, and is
covered by tests. "Unresolved critical/high defects: none" is the release claim;
evidence is the test references and the manual checks recorded in `progres.md`.

## 1. Mode classification (fail-closed)
- **Enforcement:** `mauberesec/policy/gateway.py::classify_target`,
  `authorize_assessment`.
- **Rule:** only registered lab hosts/networks classify as LOCAL_LAB; anything
  else (localhost, private IPs, unknown names) is LIVE_WHITE_HAT.
- **Tests:** `tests/security/test_policy_gateway.py`.
- **Status:** OK.

## 2. Authorization and scope binding
- **Enforcement:** `AuthorizationRecord.scope_sha256` must equal
  `Scope.sha256()`; expiry enforced; `PolicyGateway.authorize_assessment`.
- **Tests:** same file. **Status:** OK.

## 3. Destination validation
- **Enforcement:** `scope/urlcheck.py` — public-only for live; registered
  subnets for lab; metadata endpoints denied; per-hop redirect revalidation in
  `tools/website/passive.py`.
- **Tests:** `tests/unit/test_urlcheck.py`, `tests/integration/test_passive_checker.py`.
- **Status:** OK.

## 4. Docker surface (narrow by construction)
- **Enforcement:** `docker/client.py` allowlist; forbidden `--privileged`,
  socket mounts, host networking; the sole `--device /dev/kvm` path is the
  emulator method; `exec_in` restricts argv[0].
- **Tests:** `tests/unit/test_docker_client.py`,
  `tests/integration/test_scanner_container.py`, `test_emulator_orchestration.py`.
- **Status:** OK. Known trade-off: `exec` is allowlisted for emulator
  orchestration; it never receives model input.

## 5. Tool registry and agent bounds
- **Enforcement:** `ToolRegistry` + `validate_plan` + gateway step checks;
  budgets in `AgentState`; cancellation preserves partial results.
- **Tests:** `tests/unit/test_agent_planning.py`,
  `tests/security/test_agent_security.py`. **Status:** OK.

## 6. Secret handling
- **Enforcement:** `redaction.py` applied to log records, audit details,
  evidence, reports; gitleaks values withheld at parse time.
- **Tests:** `tests/security/test_logging_redaction.py`,
  `tests/unit/test_scanner_parsers.py`, `tests/unit/test_findings_reports.py`.
- **Status:** OK.

## 7. MCP trust
- **Enforcement:** explicit config; untrusted ⇒ discovery-only; shell/exec-like
  tools refused; write-capable servers refused; timeouts/output caps.
- **Tests:** `tests/unit/test_mcp.py`. **Status:** OK (residual risk documented).

## 8. Lab isolation and destructive actions
- **Enforcement:** internal bridge networks; label-scoped teardown;
  `changes_target_state` requires explicit per-run confirmation; reset
  restores baseline.
- **Tests:** `tests/integration/test_lab_manager.py`,
  `test_lab_validation.py`. **Status:** OK.

## 9. Emulator isolation
- **Enforcement:** internal network per run; adb inside the container only;
  synthetic data; verified reset; capability refusal.
- **Tests:** `tests/unit/test_dynamic_analysis.py`,
  `tests/integration/test_emulator_orchestration.py`. **Status:** OK (experimental feature flagged).

## 10. Verification honesty
- **Enforcement:** `findings/verify.py` — LLM-only claims cannot be confirmed.
- **Tests:** `tests/unit/test_findings_reports.py`. **Status:** OK.

## Findings from this review

| ID | Severity | Area | Finding | Resolution |
|---|---|---|---|---|
| SR-1 | Low | Docker surface | `exec` allowlisted for emulator orchestration | Kept; argv[0] restricted; no model input; documented |
| SR-2 | Low | MCP | Servers run as the user's process | Accepted residual risk; documented in threat model §5 |
| SR-3 | Low | Emulator | Multi-GB third-party image, opt-in only | Documented; never auto-pulled unless the user runs the command |
| SR-4 | Info | Reports | Evidence items are free-form observations | Tracked as future work in `progres.md` |

No unresolved critical or high product security defects at v1.0.0.

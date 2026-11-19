# MaubereSec AI — Threat Model (v1.0)

**Scope of this document:** threats to the *product's own security guarantees*
(the things that make MaubereSec safe to run), not the vulnerabilities it finds.

## 1. Assets

| Asset | Why it matters |
|---|---|
| Host filesystem outside explicitly selected paths | User data, SSH keys, browser profiles, cloud credentials |
| Cloud provider API keys | Billing and data exposure |
| Docker daemon control | Equivalent to host root |
| The authorization/scope decision | Legal and safety boundary of an assessment |
| Assessment evidence | May contain sensitive fragments of scanned systems |
| The user's own network | Scanning third parties without authorization is unlawful |

## 2. Trust boundaries

```
[ model output ]  --untrusted-->  [ schema validation ]  --> [ policy gateway ]  --> [ executor ]
[ scanned web/code/APK/MCP output ] --untrusted--> [ evidence pipeline ] --> [ redaction ] --> [ report ]
[ MCP server process ] --untrusted--> [ allowlist + trust flag ] --> [ bounded client ] --> [ policy gateway ]
```

The **model is never the security boundary**. Every capability is gated by
deterministic application code.

## 3. Adversaries

| Adversary | Capability | Primary mitigations |
|---|---|---|
| Malicious target (web page, repo, APK) | Supply hostile content that reaches prompts or parsers | Untrusted-content framing, injection-marker auditing, schema validation, archive-bomb limits, containers with cap_drop ALL |
| Malicious MCP server | Return hostile schemas/output, request over-broad trust | Explicit config only, untrusted-by-default (discovery-only), shell/exec tool refusal, output caps, injection auditing |
| Prompt-injection via tool output | Redirect the agent to run unintended tools | Agent executes only schema-validated plans; every step passes the policy gateway; unknown tools denied; no shell execution path exists |
| Over-scoped or unauthorized use | Aim the tool at third parties | Mode classification fail-closed, authorization records bound to the scope hash, private/metadata destination rejection |
| Compromised scanner image | Escape into the host, exfiltrate | No Docker socket, read-only mounts, network disabled by default, cap_drop ALL, no privileged mode, label=disable limited to reads |
| Curious operator / logs | Read secrets from logs or reports | Redaction on log records, audit details, evidence, and reports |
| The model provider | Retain submitted data | Explicit disclosure before first request; redaction before submission; no silent provider fallback |

## 4. Key attack paths and their controls

| Path | Control | Verified by |
|---|---|---|
| Model invents a tool | Registry check in `validate_plan` + gateway | `tests/unit/test_agent_planning.py`, `tests/security/test_agent_security.py` |
| Model changes scope/mode | Mode copied from scope; plan targets must be in scope | same |
| Injected tool output drives actions | Output is data; injection markers audited; no code path from output to execution | `tests/security/test_agent_security.py`, `tests/unit/test_mcp.py` |
| `--mode lab` against a public host | `classify_target` requires a registered lab network/host; otherwise LIVE (fail closed) | `tests/security/test_policy_gateway.py` |
| Stock exfiltration via scanner | `run_scanner` rejects host mounts except validated `:ro`; no network unless explicitly opted in | `tests/unit/test_docker_client.py`, `tests/integration/*` |
| Secrets in reports/logs | Redaction applied to log records, audit details, evidence, reports | `tests/security/test_logging_redaction.py`, `tests/unit/test_findings_reports.py` |
| Destructive lab action | `changes_target_state` tools require explicit per-run confirmation | `tests/security/test_policy_gateway.py`, `tests/integration/test_lab_validation.py` |
| Third-party MCP auto-connect | Absent config ⇒ no servers; untrusted ⇒ discovery-only | `tests/unit/test_mcp.py` |
| Emulator on an unsupported host | Refused with guidance rather than degraded isolation | `tests/unit/test_dynamic_analysis.py` |

## 5. Residual risks (accepted, documented)

1. **MCP servers run as local processes** under the user's account. Mitigated by
   explicit configuration, untrusted-by-default, allowlists, timeouts, and
   output caps — but a hostile server the user configures can still act as that
   user. Users must treat MCP configuration as a trust decision.
2. **Agent reasoning quality** is not a security guarantee; the product bounds
   what can happen, not whether the analysis is good.
3. **Container isolation depends on the host Docker daemon**, which is outside
   the product boundary. The product never mounts the socket and never uses
   privileged mode, but a compromised daemon remains root-equivalent.
4. **Emulator images are large third-party artifacts**; only images the user
   names are used, pulled from their registry.
5. **Findings can be wrong.** Verification rules prevent LLM-only claims from
   being confirmed, but a reviewer is still required for final judgement.

## 6. Explicit non-goals (see PRD §4)

No malware, persistence, stealth, evasion, credential theft, phishing, brute
force, denial-of-service, exfiltration, host/container escape, or unauthorized
data modification. No autonomous shell execution. No third-party testing
without an authorization record.

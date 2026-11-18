# MaubereSec AI — Security Policy

## 1. Non-negotiable principle

The AI model is not the security boundary. Application code enforces authorization, scope, mode, destination, tool permissions, and resource budgets.

## 2. Operating modes

### Local Lab Red-Team
Only registered, disposable, user-controlled lab targets. Use synthetic accounts and data. Deeper validation must remain inside the isolated lab. State-changing checks require explicit per-run confirmation and resettable fixtures.

### Live White-Hat
Requires explicit authorization and exact scope. Only passive and low-impact, non-destructive validation is allowed. No disruption, data extraction, credential attacks, persistence, stealth, or destructive testing.

### Local files
Only selected repository/APK paths. Prevent traversal and symlink escape. Process untrusted files in restricted containers.

## 3. Local is not established by hostname

`localhost`, `127.0.0.1`, `.local`, or a CLI flag does not establish a safe lab. Verify registered lab identity, resolved addresses, network membership, redirects, and actual connection destinations. Uncertain targets receive Live restrictions.

## 4. Docker controls

- No Docker socket in agent or scanner containers.
- No privileged containers by default.
- Non-root execution.
- Drop capabilities.
- Read-only input mounts.
- Dedicated lab networks.
- Resource limits and timeouts.
- No host networking by default.
- No host credential mounts.
- Fixed container profiles only; no model-controlled Docker arguments.

## 5. Prohibited behavior

No malware, persistence, stealth, evasion, log deletion, credential theft, phishing, brute force, denial-of-service, exfiltration, host/container escape, or unauthorized data modification.

## 6. Tool and MCP controls

Only explicitly configured tools. Every invocation passes deterministic policy validation. Tool schemas and outputs are untrusted. No unrestricted shell MCP server. No automatic MCP server installation or connection.

## 7. Cloud AI privacy

Show a disclosure before cloud submission. Redact secrets. Send only necessary snippets and summaries. Never silently change provider. Never log API keys. Local scanner-only operation should remain possible without an AI call where supported.

## 8. Stop conditions

Stop on missing authorization, out-of-scope destination, redirect escape, policy denial, unexpected tool behavior, budget exhaustion, user cancellation, or safety-check failure. Produce a partial report when possible.

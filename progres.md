# MaubereSec AI Progress

## Current milestone
v0.10 — MCP integrations

## Status
Implemented and tested (official SDK 2.3.0; live fixture-server runs) — awaiting owner validation and approval of v0.11

## Completed

### v0.1–v0.9 (approved & released)
- CLI/cloud foundation, policy/database foundation, Docker lab manager, passive
  live website assessment, source-code audit, APK static analysis, bounded
  agent, lab red-team validation, APK dynamic analysis (experimental).

### v0.10 (this milestone)
- [x] Official MCP client SDK adopted (`mcp` 2.3.0, verified importable and
      working on this Python 3.14 host; API probed before implementation).
- [x] Explicit configuration only (`mcp/config.py`): servers are listed in
      `mcp.json`; an absent file means **no servers** and nothing is contacted.
      `trusted=false` by default; `read_only` required for exposure.
- [x] Read-only discovery (`mcp/bridge.py::discover`): initialize + tools/list
      only, with server identity/protocol version recorded and audited.
- [x] Schema normalization (`mcp/normalize.py`): MCP tools become internal
      `mcp.<server>.<tool>` contracts; shell/exec/bash/sudo-like names or
      descriptions are rejected outright; write-capable servers refused;
      per-server allowlists honored; contracts are read-only and never
      lab-only.
- [x] Policy gateway on every invocation: calls run
      `PolicyGateway.check_tool_call`; unknown/undiscovered tools are denied;
      untrusted servers are discovery-only (denials audited).
- [x] Timeouts and output caps (`mcp/client.py`): asyncio deadline per
      operation and per-server byte caps with explicit truncation markers.
- [x] Untrusted content handling: outputs are framed as data by the CLI and
      injection markers are detected and audited.
- [x] Local fixture MCP server (`mcp/fixture_server.py`) with an intentional
      injection attempt, plus CLI `mauberesec mcp list|call`, and a documented
      `config/mcp.example.json`.

## In progress
- None.

## Automated tests
- Total: 233 passed, 1 skipped (+18 this milestone).
- Unit/security: config validation (absent = no servers, malformed rejected),
  shell-like tool rejection (names and descriptions), write-server refusal,
  allowlists, sanitized contract naming, untrusted discovery-only behaviour,
  unconfigured server never contacted, injection markers audited, every call
  audited, unknown tool denied by policy, output truncation, timeout errors,
  example config disabled by default.
- Live runs: discovery and invocation against the local fixture server via the
  official SDK (initialize/list/call, untrusted refusal, trusted call).
- mypy strict (69 files) and ruff clean.

## Manual tests (Linux, this host)
- `mcp list` with two configured fixture servers: discovery showed
  `msai-fixture v0.10.0 (protocol 2024-11-05)` and three tools.
- `mcp call fixture ...` (untrusted) → refused with an explicit explanation.
- `mcp call fixture-trusted echo` → returned `echo: hi`, output labelled
  untrusted.

## Known issues
- Only read-only MCP integrations are exposed in this milestone (roadmap:
  "add approved scanner MCP integrations selectively"); write-capable servers
  are refused by design.
- MCP servers run as local subprocesses under the user's account (inherent to
  stdio MCP); mitigation is explicit configuration, untrusted-by-default
  trust, policy gating, timeouts, and output caps.

## Next permitted work
Only tasks in v0.11 — Findings verification and reports (after owner approval).

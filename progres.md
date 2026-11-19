# MaubereSec AI Progress

## Current milestone
v0.11 — Findings verification and reports

## Status
Implemented and tested (real scan → schema-validated report) — awaiting owner validation and approval of v1.0

## Completed

### v0.1–v0.10 (approved & released)
- CLI/cloud foundation, policy/database foundation, Docker lab manager, passive
  live website assessment, source-code audit, APK static analysis, bounded
  agent, lab red-team validation, APK dynamic analysis (experimental),
  MCP integrations.

### v0.11 (this milestone)
- [x] Versioned finding schema (`findings/schema.py`, schema_version 1.0):
      severity and confidence are independent; `source` (tool/llm/human)
      recorded; evidence as structured {kind, locator, detail} items;
      remediation carried per finding.
- [x] Verification engine (`findings/verify.py`): **an LLM-only claim can never
      be confirmed** — confirmation requires tool/human-backed evidence with a
      reproducible locator plus a reproduction result; refutation requires
      deterministic evidence (false-positive), and non-reproduction is
      recorded as not-reproducible rather than dropped.
- [x] Evidence correlation (`findings/correlate.py`): same issue at the same
      locator across tools merges into one finding with unioned evidence and
      the most conservative severity/confidence; volatile identifiers
      (CVE/GHSA/hashes) are stripped for comparison; different locations stay
      separate (never over-merged).
- [x] Report generation (`reports/generator.py`): Markdown + JSON with scope,
      mode, authorization reference, scope hash, tools used/available,
      limitations, untested areas, severity/verification summary; partial runs
      (cancelled/failed/running) are labelled PARTIAL; findings missing
      remediation are flagged; the architecture §11 layout is written
      (report.md, report.json, findings.json, metadata.json).
- [x] Redaction: every rendered field passes through the redaction module —
      reports never contain secrets (tested with a planted key).
- [x] Shipped JSON Schema + validation (`report schema` command; validated in
      tests with jsonschema).
- [x] CLI: `report generate|show|schema`, top-level `history`, and
      `assessment show`.

## In progress
- None.

## Automated tests
- Total: 252 passed, 1 skipped (+19 this milestone).
- Unit/security: LLM-only never confirmed (even when "reproduced"); tool-backed
  reproduction confirmed; non-reproduction marked; refutation requires
  evidence; correlation merge/keep-separate rules; volatile-ID stripping;
  report shape; **no secrets in JSON or Markdown**; LLM claim not confirmed in
  the report; partial labelling; schema validation with jsonschema; §11 layout;
  missing-remediation flag; CLI history/show/generate paths.
- mypy strict (76 files) and ruff clean.

## Manual tests (Linux, this host)
- Real passive scan of `https://example.com` (authorized) → `report generate`
  produced report.md/report.json/findings.json/metadata.json; the JSON
  validated against the shipped schema; 5 findings, partial=false, tools
  recorded as `passive.http_headers`.

## Known issues
- Evidence items are derived from stored free-form evidence text (one
  observation item per finding); richer per-tool evidence typing is future work.
- Verification currently requires an explicit reproduction/refutation call
  (no automatic re-execution harness yet); statuses therefore default to
  needs-review until a reviewer or a future re-run promotes them.

## Next permitted work
Only tasks in v1.0 — Stable release (after owner approval).

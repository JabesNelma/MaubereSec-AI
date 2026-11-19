# MaubereSec AI Progress

## Current milestone
v0.5 — Local source-code audit

## Status
Implemented and tested (incl. real scanner runs in containers) — awaiting owner validation and approval of v0.6

## Completed

### v0.1–v0.4 (approved & released)
- CLI foundation + cloud model, policy/database foundation, Docker lab manager,
  passive live website assessment.

### v0.5 (this milestone)
- [x] Path safety (`mauberesec/scope/pathcheck.py`): canonicalization, symlinked
      root rejection, per-entry symlink escape detection (escapes skipped + reported).
- [x] File inventory (`tools/source_audit/inventory.py`): generated/binary/oversized
      exclusions, secret-hint files tracked and excluded from any cloud context,
      max_files/max_total_bytes/max_file_bytes limits.
- [x] Container scanner execution (`DockerClient.run_scanner`): strictly read-only
      source mount (validated; general `docker run` still rejects host mounts),
      `--network none` default (opt-in bridge only for rule/advisory downloads),
      cap_drop ALL, no-new-privileges, read-only rootfs, tmpfs, fixed entrypoint/env.
      `label=disable` (container-only) needed on SELinux hosts; user files never relabeled.
- [x] Adapters (`tools/source_audit/adapters.py`): Semgrep (semgrep/semgrep:1.86.0),
      Gitleaks (zricethezav/gitleaks:v8.24.3), OSV-Scanner (ghcr.io/google/osv-scanner:v1.9.2);
      fixed commands only; pre-pull to keep stdout clean; JSON parsers; secret values
      withheld (gitleaks metadata + `--redact` only); deterministic dedup.
- [x] Dependency manifest analysis (`tools/source_audit/manifest.py`):
      requirements.txt / package.json / go.mod summaries — no installs, no execution.
- [x] CLI `mauberesec audit <path>` (+ `--inventory-only`): LOCAL_FILE mode assessment,
      policy-checked tool calls, ToolRun + Finding persistence, audit events.
- [x] Tool contracts: static.semgrep, static.gitleaks, static.osv_scanner registered.

## In progress
- None.

## Automated tests
- Total: 142 passed (+23 this milestone).
- Unit: path canonicalization/symlink rejection/escape, inventory exclusions and
  limits, manifest parsing, scanner JSON parsers, secret-withholding, dedup.
- Integration (real Docker): scanner cannot write the read-only source mount,
  scanner has no interfaces beyond loopback (network=none), adapter plumbing
  produces parsed findings from a mounted fixture.
- Security: relative host path rejected by run_scanner; general run still rejects
  host mounts (incl. :ro); fixed-command guarantees; env not project-controlled;
  gitleaks secrets absent from model records and persisted DB rows.
- mypy strict (37 files) and ruff clean.

## Manual tests (Linux, this host, real scanners)
- `mauberesec audit <copy of this repo>` with planted issues:
  - Semgrep found the planted SQL-string finding (2 findings, incl. the real
    f-string PRAGMA in db.py).
  - Gitleaks found 3 planted/test secret matches — values withheld from findings
    and DB (verified: `AKIAIOSFODNN7EXAMPLE` absent from stored JSON).
  - OSV-Scanner ran clean (no vulnerable manifests in fixture).
- Inventory correctly excluded node_modules/.git/binaries/oversized files and
  flagged .env as secret-hint.

## Known issues
- Semgrep/OSV require outbound network for rule packs / advisory DB (bridge only;
  documented per-adapter); fully offline operation needs vendored rule caches
  (future enhancement).
- OSV-Scanner reports against manifests it recognizes; lockfile-less projects get
  partial coverage.
- Scanner stdout size cap is the run budget's max_response_bytes equivalent at
  64MB tmpfs; extremely noisy repos may truncate (tool_run records it).

## Next permitted work
Only tasks in v0.6 — APK static analysis (after owner approval).

# MaubereSec AI Progress

## Current milestone
v0.4 — Passive live website assessment

## Status
Implemented and tested — awaiting owner validation and approval of v0.5

## Completed

### v0.1 (approved)
- CLI foundation, provider-neutral model interface, OpenAI adapter, secret redaction,
  cloud disclosure, hardened Dockerfile/compose.

### v0.2 (approved)
- XDG paths, SQLite + migrations, record schemas, tool contract + registry,
  deterministic policy gateway (fail-closed classification, authorization, audit).

### v0.3 (approved)
- Allowlisted Docker CLI wrapper, hardened lab profiles (internal network, limits,
  cap_drop ALL), lab lifecycle (create/verify/teardown/reset, label-scoped),
  persisted lab registrations feeding the policy registry, CLI lab commands.

### v0.4 (this milestone)
- [x] URL normalization (`mauberesec/scope/urlcheck.py`): http/https only, no
      credentials/query/fragment, scheme inference, port validation.
- [x] DNS/IP destination validation for live targets: private, loopback,
      link-local (incl. 169.254.169.254), multicast, reserved, unspecified, and
      metadata hostnames (metadata.google.internal) all rejected — fail closed.
- [x] Lab destination validation: every resolved address must be inside a
      registered lab subnet.
- [x] Passive HTTP checker (`mauberesec/tools/website/passive.py`):
      - GET-only, no cookies/credentials sent, passive by construction.
      - Manual redirect following with per-hop destination revalidation
        (redirects cannot escape scope or reach forbidden ranges).
      - Security header checks (HSTS, CSP, X-Content-Type-Options,
        X-Frame-Options, Referrer-Policy) and cookie attribute checks
        (Secure, HttpOnly, SameSite) → FindingRecords.
      - Budgets: request count, rate interval, per-request timeout, response
        size cap (streamed), redirect limit.
- [x] Evidence normalization: Evidence summary (status, headers, cookies,
      redirect chain, notes) persisted as redacted ToolRunRecord summary.
- [x] CLI `mauberesec scan <url>`: live requires `--auth-reference` +
      `--authorized-by` (AuthorizationRecord bound to scope hash, 24h validity);
      registered-lab targets classify LOCAL_LAB without authorization; clean
      errors for unreachable targets.

## In progress
- None.

## Automated tests
- Total: 119 passed.
- Unit: URL normalization (schemes, credentials, query/fragment, ports),
  destination rejection matrix (private/loopback/link-local/metadata/multicast/
  reserved), lab subnet checks.
- Integration (mocked HTTP): header/cookie findings, redirect following,
  redirect-to-private blocked, relative redirects, redirect limit, request
  budget, response size cap, validator on initial URL.
- Security: live scan without/with partial authorization blocked; private and
  metadata targets rejected; lab flag cannot bypass; GET-only request policy
  (spy transport); audit trail persisted for blocked scans.
- mypy strict & ruff clean (31 files).

## Manual tests (Linux, this host)
- Lab target scan: classified `local_lab`, no authorization needed; internal
  network unreachable from host reported cleanly (checks must run from the lab
  network).
- Live scan against https://example.com with authorization flags: full flow OK —
  headers fetched, 5 low-severity findings produced and persisted.

## Known issues
- TLS metadata is minimal (scheme recorded; certificate/protocol details
  arrive with a later milestone or tool adapter).
- Live passive checks run from the host; running scanners inside the lab
  network (via lab-attached containers) arrives in later milestones.
- Rate limiter is per-checker, not persisted across runs.

## Next permitted work
Only tasks in v0.5 — Local source-code audit (after owner approval).

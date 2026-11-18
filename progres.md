# MaubereSec AI Progress

## Current milestone
v0.3 — Docker isolation and local lab manager

## Status
Implemented and tested (incl. live Docker integration tests) — awaiting owner validation and approval of v0.4

## Completed

### v0.1 (approved)
- CLI foundation, provider-neutral model interface, OpenAI adapter, secret redaction,
  cloud disclosure, hardened Dockerfile/compose.

### v0.2 (approved)
- XDG paths, SQLite + migrations (6 tables), record schemas (scope/authorization/
  mode/budgets/findings/audit), tool contract + registry, deterministic policy
  gateway with fail-closed classification and full audit persistence.

### v0.3 (this milestone)
- [x] Fixed Docker CLI wrapper with allowlisted subcommands
      (`mauberesec/docker/client.py`): rejects `--privileged`, docker-socket mounts,
      host-path binds, `--network host`/`--pid host`, and non-allowlisted subcommands;
      named volumes allowed.
- [x] Lab profiles (`LabProfile`/`LabService`): private /24 subnet required,
      per-service memory/CPU/PID limits, cap-drop-ALL with a capability allowlist
      (CHOWN/SETUID/SETGID/NET_BIND_SERVICE/DAC_OVERRIDE/KILL only), read-only rootfs
      + tmpfs, health checks.
- [x] Lab manager (`mauberesec/docker/labs.py`): create (dedicated **internal**
      bridge network per lab, labeled resources), verify (network labels, container
      status/health/privileged checks), teardown (only label-matching resources),
      reset; partial-failure rollback.
- [x] Lab registration persisted in `lab_registrations` (`LabStore`) and bridged
      into the policy `LabRegistry` — unregistering a lab immediately revokes
      LOCAL_LAB classification.
- [x] CLI: `mauberesec lab list|register|verify|teardown|reset`.
- [x] Built-in template `demo-web` (nginx:1.27-alpine, 10.66.7.0/24) +
      `docker/labs/README.md`.
- [x] No host ports published, no host mounts, no Docker socket anywhere.

## In progress
- None.

## Automated tests
- Total: 85 passed.
- Unit: docker-client allowlist validation, lab profile validation, records/paths/etc.
- Integration (real Docker daemon): lab lifecycle create→verify→reset→teardown;
  teardown removes only label-matching resources (sentinel container + second lab
  survive); container/network hardening asserted from live inspect output.
- Security: unregistered subnet fails closed; registered lab grants LOCAL_LAB;
  unregister revokes; policy gateway blocks lab assessment after unregistration;
  forbidden docker args rejected.
- Type checks: mypy strict — clean (26 files).
- Lint: ruff check + format — clean.

## Manual tests (Linux, this host)
- `mauberesec lab register demo-web` → network + container created, registered.
- `lab verify` → ok=true, health=healthy, privileged=false.
- Live inspect: network internal=true + labels; container mem=128MiB, pids=64,
  caps=[CHOWN,SETGID,SETUID], binds=[], ports=none, readonly=true,
  no-new-privileges.
- `lab reset` → removed and recreated, still registered, verify ok.
- `lab teardown` → only lab-labeled resources removed, registration cleared.
- Container image rebuilt; `lab list` in agent container reports docker CLI absent
  (by design — lab control runs on host).

## Known issues
- `docker compose` plugin still missing on dev host (doctor reports it); lab
  manager therefore uses the docker CLI directly through the fixed wrapper.
- Only one built-in template (demo-web); more training labs arrive with later
  milestones.
- macOS / Windows-WSL2 untested.

## Next permitted work
Only tasks in v0.4 — Passive live website assessment (after owner approval).

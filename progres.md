# MaubereSec AI Progress

## Current milestone
v0.9 — APK dynamic analysis in an isolated emulator (experimental)

## Status
Implemented and tested (orchestration verified end-to-end; host capability detection verified both ways) — awaiting owner validation and approval of v0.10

## Completed

### v0.1–v0.8 (approved & released)
- CLI/cloud foundation, policy/database foundation, Docker lab manager, passive
  live website assessment, source-code audit, APK static analysis, bounded
  agent, controlled local-lab red-team validation.

### v0.9 (this milestone)
- [x] Host capability detection (`android/hostcheck.py`): /dev/kvm presence and
      access, CPU virtualization flags (vmx/svm), docker availability. An
      unsupported host is refused with an actionable explanation (exit 3) —
      isolation is never silently degraded. `doctor` now reports an
      `android-emulator` line.
- [x] Synthetic fixtures only (`android/fixtures.py`): fixed synthetic account
      (`.invalid` email) and dataset files with a marker; unit tests assert no
      realistic secret patterns exist anywhere in the fixtures.
- [x] Fixed container entry script (`android/container/emulator_entry.sh`):
      waits for boot, pushes the synthetic dataset, installs the APK,
      launches it, captures logcat/process/package observations, and emits one
      JSON line. All adb calls target the container's own emulator — the
      host's adb is never used, so a personal device cannot be targeted.
- [x] Emulator orchestration (`android/emulator.py`): per-run **internal**
      Docker network (egress stays inside the boundary), detached emulator
      container with `--device /dev/kvm`, fixed `docker exec` of the entry
      script, teardown of container + network, and **verified reset** (each run
      uses a brand-new container and the runner asserts the identity differs
      from the previous run). Image-level snapshots (docker commit) are
      deliberately not used, keeping the Docker allowlist minimal.
- [x] Narrow Docker API additions (`docker/client.py`): the only path allowed to
      pass `--device /dev/kvm` (run_emulator_container), `exec_in` restricted to
      a permitted argv[0] set, `remove_container`, `image_exists`, and
      `("exec",)`/`("image","inspect")` in the allowlist. Generic `run` still
      rejects host mounts, privileged mode, and host networking.
- [x] CLI `mauberesec apk dynamic <apk> [--package] [--image] [--logcat-seconds]
      [--dry-run]`, marked EXPERIMENTAL; dry-run prints the plan without
      executing; package can be auto-derived from the static analyzer.
- [x] Clearly marked experimental; the roadmap's platform caveat is implemented
      as an explicit capability gate rather than an assumption.

## In progress
- None.

## Automated tests
- Total: 215 passed, 1 skipped (+16 this milestone).
- Unit: capability detection (missing KVM, missing virtualization flags),
  refusal message content, fixture synthetic-only assertions, CLI refusal
  (exit 3) and dry-run, package requirement, docker client allowlist/exec
  restrictions, emulator API validation errors.
- Integration (real Docker, stub emulator image): full orchestration
  end-to-end — internal network created, detached container, fixed exec of the
  entry script, synthetic push, install, launch, logcat capture, teardown, and
  verified reset across two runs (distinct container ids). A real-emulator
  opt-in test runs when MSAI_EMULATOR_IMAGE is set.
- mypy strict (62 files) and ruff clean.

## Manual tests (Linux, this host — has KVM)
- `doctor` reports `android-emulator: supported (KVM available, docker present)`.
- `apk dynamic <apk> --dry-run` prints the plan (package auto-detected as
  com.example.vuln from the static analyzer) and executes nothing.
- Simulated unsupported host: exit code 3 with an explanation and a pointer to
  `mauberesec apk analyze`.

## Known issues
- A real emulator image (`budtmo/docker-android:emulator_11.0`, multi-GB) is not
  downloaded in CI; the opt-in test `MSAI_EMULATOR_IMAGE` covers it when
  available. Orchestration correctness is verified against a stub image.
- Dynamic analysis remains EXPERIMENTAL pending platform matrix evidence
  (roadmap requirement), and no findings are auto-generated from logcat — the
  capture is evidence for human review in this milestone.

## Next permitted work
Only tasks in v0.10 — MCP integrations (after owner approval).

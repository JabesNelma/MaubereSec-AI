# MaubereSec AI Progress

## Current milestone
v0.6 — APK static analysis

## Status
Implemented and tested (incl. real container analysis of a crafted APK) — awaiting owner validation and approval of v0.7

## Completed

### v0.1–v0.5 (approved & released)
- CLI/cloud foundation, policy/database foundation, Docker lab manager,
  passive live website assessment, local source-code audit.

### v0.6 (this milestone)
- [x] Host-side validation (`tools/apk/validate.py`): path/size cap (500 MB),
      ZIP magic check, symlink rejection, SHA-256, quick central-directory probe.
- [x] Pure-python AXML parser (`tools/apk/container/axml.py`): string pool
      (UTF-8/UTF-16), start/end elements, typed attribute values
      (string/int/bool/reference), CDATA — unit-tested against a hand-built
      binary manifest.
- [x] Container analyzer (`tools/apk/container/apk_analyzer.py`, stdlib-only
      script mounted read-only into python:3.12-alpine, network none):
      - AndroidManifest review: dangerous permissions, exported components
        (unprotected → medium, provider unprotected → high, protected → low),
        debuggable (high), usesCleartextTraffic (medium), allowBackup (low),
        outdated targetSdk (< 24 → low).
      - Network security config (res/xml/*): cleartextTrafficPermitted=true.
      - Embedded secret indicators (DEX printable strings + assets/res-raw/
        text files): AWS keys, Google/OpenAI keys, GitHub tokens, JWTs,
        password assignments, private-key markers — **values never reported**.
      - ZIP-bomb limits: entry count ≤ 20k, per-entry ≤ 200 MB, total ≤ 2 GB,
        compression-ratio guard; violations abort with clean JSON errors.
- [x] Host adapter (`tools/apk/analysis.py`): stages the APK into a controlled
      input location (arch §9 step 3), runs the container, parses JSON into
      FindingRecords with artifact evidence + confidence.
- [x] CLI `mauberesec apk analyze <path>` (+ `--metadata-only`); assessment in
      LOCAL_FILE mode with kind=APK; policy gateway now maps apk_static → APK
      targets. APK is never installed or executed on the host.
- [x] `DockerClient.run_scanner` supports extra validated read-only mounts.

## In progress
- None.

## Automated tests
- Total: 162 passed (+20 this milestone).
- Unit: AXML parsing (attributes, typed values), manifest findings coverage,
  secret-withholding assertions, zip-bomb ratio/entry/size rejections,
  malformed ZIP fail-safe, missing manifest rejection, path validation.
- Integration (real Docker): analyzer container end-to-end on a fixture APK
  (findings + secrets absent from output), corrupt APK rejected inside the
  container, fixed-command verification (python3 analyzer — APK is data only).
- Security: CLI rejects non-APK/missing/symlink paths; secret values absent
  from records and audit events; size-cap enforcement.
- mypy strict (44 files) and ruff clean.

## Manual tests (Linux, this host)
- `mauberesec apk analyze /tmp/msai-apk/vuln-app.apk` (crafted APK with
  debuggable, cleartext, CAMERA, exported activity, targetSdk 21, planted
  AWS/OpenAI/password secrets): 8 findings produced, secrets withheld from
  output and database.
- `--metadata-only` path returns SHA-256 without any container run.

## Known issues
- Manifest attributes rely on typical aapt layouts (attrStart 0x14); exotic
  packers may need a fuller AXML implementation (tests make the contract clear).
- DEX analysis is string-level indicator scanning; full decompilation
  (jadx/apkanalyzer) is reserved for later milestones per roadmap wording.
- networkSecurityConfig is located by scanning res/xml/*.xml (resource-ID to
  file mapping is not resolved).

## Next permitted work
Only tasks in v0.7 — Bounded agent planning and analysis (after owner approval).

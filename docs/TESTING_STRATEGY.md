# MaubereSec AI — Testing Strategy

## 1. Test layers

- Unit: config, provider selection, scope, mode classification, URL/IP checks, path safety, schemas, redaction, finding normalization.
- Integration: cloud provider mocked endpoints, SQLite, Docker wrapper, scanner parsers, MCP fixture server.
- Security: traversal, symlink escape, redirect escape, private IP rejection, prompt injection, malicious tool output, oversized files, archive bombs, secret leakage, container privilege checks, budget exhaustion.
- E2E: local Docker lab only, local fixture website, fixture source repository, sample APK fixtures, report generation.

## 2. Platform matrix

Test on:
- Ubuntu Linux with Docker Engine.
- macOS with Docker Desktop.
- Windows with Docker Desktop + WSL2.

Do not claim full platform support until the matrix has actual test evidence. APK dynamic emulator testing has separate host virtualization requirements.

## 3. Commands

Expose scripts or documented commands for:

```bash
ruff check .
ruff format --check .
mypy mauberesec
pytest
docker compose config
docker compose build
```

Add targeted security and integration test markers.

## 4. Mandatory security cases

- `--mode lab` cannot bypass lab registration.
- `localhost` cannot classify an arbitrary public redirect as local.
- Live mode blocks destructive tool profiles.
- Redirects cannot escape scope.
- DNS results are validated.
- Agent cannot invent tools or execute shell strings.
- Agent cannot modify authorization.
- Docker socket is not mounted.
- Containers are non-root and not privileged by default.
- APK archive/decompression limits work.
- APK never executes on host.
- Secrets are redacted from logs, model context, and reports.
- Cloud provider failure does not silently switch provider.
- Ctrl+C cancels subprocesses and agent loop.

## 5. Release gates

No milestone is complete until relevant tests, lint, type checks, container checks, manual tests, documentation, and `progres.md` updates pass. Never weaken a security test just to obtain a green test run.

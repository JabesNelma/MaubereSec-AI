# Dependency and Container Review (v1.0)

Reviewed at v1.0.0. Dependencies are declared in `pyproject.toml` with lower
bounds; the container pins the Python base image.

## Runtime dependencies

| Package | Purpose | Rationale / review notes |
|---|---|---|
| `typer` | CLI framework | Small, well-maintained, no network surface |
| `pydantic` (+`pydantic-settings`) | Schemas/validation | Central to the "model output is data" guarantee |
| `httpx` | HTTP client | Used with explicit timeouts; redirect handling is manual |
| `structlog` | Structured logging | Redaction processor runs before rendering |
| `mcp` | Official MCP SDK | Used only through `mcp/client.py`, which bounds time and output |

## Development-only dependencies

`pytest`, `pytest-asyncio`, `respx` (HTTP mocking), `ruff`, `mypy`,
`jsonschema` (report schema validation).

## Container images referenced

| Image | Used for | Notes |
|---|---|---|
| `python:3.12-slim-bookworm` | CLI runtime image (`docker/Dockerfile`) | Non-root user `msai`, read-only-rootfs compatible |
| `python:3.12-alpine` | APK analyzer, lab probe, emulator stub in tests | Fixed commands; no network unless explicitly required |
| `semgrep/semgrep:1.86.0` | Source audit | Pinned; network enabled only to fetch rule packs |
| `zricethezav/gitleaks:v8.24.3` | Source audit | Pinned; `--redact`; values never parsed into findings |
| `ghcr.io/google/osv-scanner:v1.9.2` | Dependency advisories | Pinned; network enabled only for api.osv.dev |
| `nginx:1.27-alpine` | `demo-web` training lab | Hardened with cap allowlist and tmpfs |
| `budtmo/docker-android:emulator_11.0` | APK dynamic (experimental) | Default only; opt-in, pulled only when the user runs the command |

## Review checklist

- [x] No dependency performs network I/O at import time.
- [x] Every subprocess invocation is allowlisted and argument-validated.
- [x] No dependency is used to execute scanned content.
- [x] Container images are pinned by tag; release builds should pin digests
      (tracked as release-time task for distribution builds).
- [x] Image scanning is recommended before publishing derived images
      (`docker scout`/`trivy`) — not automated in this milestone.

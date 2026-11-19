# MaubereSec AI

Terminal-first AI security assessment agent (Python + Docker, cloud AI only).

**Status:** **v1.0.1 — stable release.** See [progres.md](progres.md) for the PRD
acceptance checklist and [docs/ROADMAP.md](docs/ROADMAP.md) for the plan.

Documentation: [install](docs/INSTALL.md) · [CLI reference](docs/CLI.md) ·
[threat model](docs/THREAT_MODEL.md) · [security review](docs/SECURITY_REVIEW.md) ·
[support matrix](docs/SUPPORT_MATRIX.md) · [dependencies](docs/DEPENDENCIES.md)

## Requirements

- Python >= 3.11 (developed on 3.14; container image uses 3.12)
- Docker (for container workflows; `doctor` reports availability)
- One cloud provider account (v0.1: OpenAI)

## Install (one command)

```bash
curl -fsSL https://raw.githubusercontent.com/JabesNelma/MaubereSec-AI/v1.0.1/install.sh | sh
```

The installer creates an isolated virtualenv in `~/.local/share/mauberesec`,
links the `mauberesec` command into `~/.local/bin`, and never uses `sudo`.
Re-running the same command upgrades in place. If `~/.local/bin` is not on
your `PATH`, the installer prints the one-line fix.

## Configure (one key)

```bash
export OPENAI_API_KEY="<your key>"
```

That is all that is required. With only the key set, the CLI uses provider
`openai` and model `gpt-4o-mini`. To choose another model:

```bash
export MSAI_MODEL="<model-id from: mauberesec models list>"
```

API keys are read from the environment only. They never appear in logs,
reports, or config output, and there is no silent fallback to another
provider. Without a key the CLI stays unconfigured and fails with a clear
message.

## Install from source (development)

```bash
git clone https://github.com/JabesNelma/MaubereSec-AI.git
cd MaubereSec-AI
python3 -m venv .venv
.venv/bin/pip install -e . --group dev
```

## Usage

```bash
mauberesec --help
mauberesec --version
mauberesec doctor          # environment and platform checks
mauberesec config show     # secret-free resolved configuration
mauberesec models list     # provider model list (shows cloud disclosure)
mauberesec models test     # credential + connectivity + model check

mauberesec lab list        # available training-lab templates
mauberesec lab register demo-web   # create + register a local lab
mauberesec lab verify demo-web     # network/health/hardening verification
mauberesec lab reset demo-web      # teardown + fresh create
mauberesec lab teardown demo-web   # remove only this lab's resources

# Controlled red-team validation inside a registered disposable lab
mauberesec lab test demo-web                        # safe (read-only) checks
mauberesec lab test demo-web --confirm-state-change # allow the synthetic-login probe
mauberesec lab test demo-web --reset-after          # restore the lab baseline afterwards

# Passive scan: live targets require explicit authorization
mauberesec scan https://example.com --auth-reference CONTRACT-1 --authorized-by owner
# Registered lab targets need no authorization (classification is verified)
mauberesec scan http://10.66.7.10/

# Local source-code audit (read-only containerized scanners; no code execution)
mauberesec audit ./my-project
mauberesec audit ./my-project --inventory-only

# APK static analysis (never installed or executed; runs in a restricted container)
mauberesec apk analyze ./application.apk
mauberesec apk analyze ./application.apk --metadata-only

# EXPERIMENTAL dynamic analysis in a disposable emulator (requires KVM;
# refuses clearly when unsupported). Synthetic data only.
mauberesec apk dynamic ./application.apk --dry-run
mauberesec apk dynamic ./application.apk --package com.example.app

# MCP integrations (explicit config only; nothing auto-connects)
cp config/mcp.example.json ~/.config/mauberesec/mcp.json   # then edit
mauberesec mcp list                                        # read-only discovery
mauberesec mcp call <server> <tool> --args '{"text":"hi"}'  # trusted servers only

# Reports and history (redacted; JSON validates against the shipped schema)
mauberesec history
mauberesec assessment show <assessment-id>
mauberesec report generate <assessment-id> --out ./reports
mauberesec report schema

# Bounded agent: plan only, or plan + execute (deterministic by default)
mauberesec agent plan ./my-project --goal "find hardcoded secrets"
mauberesec agent run ./my-project --goal "find hardcoded secrets" --max-steps 10
mauberesec agent run https://example.com --use-ai --auth-reference C-1 --authorized-by owner
```

## Docker

```bash
docker build -f docker/Dockerfile -t mauberesec/cli:0.1.0 .
docker run --rm --read-only --cap-drop ALL --tmpfs /tmp mauberesec/cli:0.1.0 --version
```

`docker/compose.yaml` provides the hardened development service
(non-root, read-only rootfs, dropped capabilities, resource limits, no
Docker socket, no host network, no privileged mode).

## Development checks

```bash
ruff check . && ruff format --check .
mypy mauberesec
pytest
```

## What is included at v1.0

- Authorized passive website assessment, local source-code audit, APK static
  analysis, and experimental APK dynamic analysis in a disposable emulator.
- Disposable local labs with controlled red-team validation behind explicit
  per-run confirmation.
- Bounded agent planning/execution and explicit-only MCP integrations.
- Versioned findings with verification rules (LLM-only claims can never be
  confirmed) and redacted Markdown/JSON reports.

## Release gate

```bash
scripts/release_check.sh --with-containers
```

Runs lint, type checks, the full test suite, CLI smoke tests, the container
build, a hardened container run, and compose syntax validation.

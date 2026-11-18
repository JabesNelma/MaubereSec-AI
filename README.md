# MaubereSec AI

Terminal-first AI security assessment agent (Python + Docker, cloud AI only).

**Status:** v0.1 — Python CLI and cloud model foundation. See [docs/ROADMAP.md](docs/ROADMAP.md) and [progres.md](progres.md).

## Requirements

- Python >= 3.11 (developed on 3.14; container image uses 3.12)
- Docker (for container workflows; `doctor` reports availability)
- One cloud provider account (v0.1: OpenAI)

## Install (development)

```bash
python3 -m venv .venv
.venv/bin/pip install -e . --group dev
```

## Configure

```bash
cp .env.example .env   # then fill values, or export directly:
export MSAI_PROVIDER="openai"
export MSAI_MODEL="<model-id from models list>"
export OPENAI_API_KEY="<your key>"
```

API keys are read from the environment only. They never appear in logs,
reports, or config output, and there is no silent fallback to another
provider.

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

# Passive scan: live targets require explicit authorization
mauberesec scan https://example.com --auth-reference CONTRACT-1 --authorized-by owner
# Registered lab targets need no authorization (classification is verified)
mauberesec scan http://10.66.7.10/
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

## Scope of v0.1

CLI foundation and one cloud provider only. No scanners, agent tool
execution, website scanning, APK analysis, or MCP integration yet —
these arrive in later roadmap milestones.

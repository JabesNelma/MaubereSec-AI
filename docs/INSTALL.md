# Installation, Upgrade, and Verification (v1.0)

## Requirements

| Requirement | Detail |
|---|---|
| Python | >= 3.11 (developed and tested on 3.14; container image uses 3.12) |
| Docker | Engine or Desktop, for scanner/lab/emulator containers (CLI must be on PATH) |
| Cloud AI (optional) | Only for `models *` and `agent --use-ai`; not needed for scanners |
| Hardware virtualization (optional) | Only for `apk dynamic` (KVM on Linux) |

## Install (development / from source)

```bash
git clone <repo> && cd MaubereSec-AI
python3 -m venv .venv
.venv/bin/pip install -e . --group dev     # runtime + test/lint tooling
.venv/bin/mauberesec --version             # expect: mauberesec 1.0.0
```

## Configure

```bash
cp .env.example .env             # cloud provider/model/key (optional)
export MSAI_PROVIDER=openai      # or set in .env and source it
export MSAI_MODEL=<model-id>
export OPENAI_API_KEY=<key>

cp config/mcp.example.json ~/.config/mauberesec/mcp.json   # MCP (optional)
```

Config/data paths (XDG with platform fallbacks):
- config: `$XDG_CONFIG_HOME/mauberesec/` (macOS: `~/Library/Application Support/mauberesec/config`)
- data:   `$XDG_DATA_HOME/mauberesec/`   (macOS: `~/Library/Application Support/mauberesec/data`)

## Verify the installation

```bash
.venv/bin/mauberesec doctor                 # environment + platform limitations
.venv/bin/ruff check . && .venv/bin/mypy mauberesec && .venv/bin/pytest
scripts/release_check.sh                    # full release gate (incl. container build)
```

## Upgrade

```bash
git fetch --tags && git checkout v1.0.0
.venv/bin/pip install -e . --group dev      # re-install to pick up new deps
.venv/bin/mauberesec doctor
```

The SQLite store migrates automatically on open (`PRAGMA user_version`); no
manual migration step is required. Back up `$XDG_DATA_HOME/mauberesec/*.sqlite3`
before upgrading if you keep long-lived assessment history.

## Uninstall

```bash
.venv/bin/pip uninstall mauberesec        # remove the CLI
rm -rf ~/.config/mauberesec ~/.local/share/mauberesec   # config + history
docker image rm mauberesec/cli:1.0.0      # container image, if built
```

## Troubleshooting

| Symptom | Cause | Action |
|---|---|---|
| `doctor` reports `docker-compose FAIL` | Compose plugin not installed | Install the plugin, or use the documented `docker build`/`docker run` commands |
| `docker CLI not found` | Docker not on PATH | Install Docker; lab/scan/scanner commands require it |
| `apk dynamic` exits 3 | No hardware virtualization | Enable VT-x/AMD-V + KVM; add your user to the `kvm` group; static analysis still works |
| `models test` fails with auth error | Invalid/missing key | Set `<PROVIDER>_API_KEY`; there is no fallback provider by design |

# Installation, Upgrade, and Verification (v1.0.1)

## Requirements

| Requirement | Detail |
|---|---|
| Python | >= 3.11 (developed and tested on 3.14; container image uses 3.12) |
| Docker | Engine or Desktop, for scanner/lab/emulator containers (CLI must be on PATH) |
| Cloud AI (optional) | Only for `models *` and `agent --use-ai`; not needed for scanners |
| Hardware virtualization (optional) | Only for `apk dynamic` (KVM on Linux) |

## Install (one command)

```bash
curl -fsSL https://raw.githubusercontent.com/JabesNelma/MaubereSec-AI/v1.0.1/install.sh | sh
```

The installer:

- creates an isolated virtualenv in `~/.local/share/mauberesec/venv`;
- installs the release tarball from GitHub (no git clone required);
- links `mauberesec` into `~/.local/bin`;
- never runs `sudo` and never modifies the system Python;
- upgrades in place when re-run.

Environment overrides: `MSAI_VERSION`, `MSAI_REPO`, `MSAI_HOME`,
`MSAI_BIN_DIR`, `MSAI_PYTHON`, `MSAI_INSTALL_URL`, `MSAI_TARBALL_SHA256`,
`MSAI_MODIFY_PATH`. Flags: `--version X`, `--force`, `--uninstall`, `--help`.

If `~/.local/bin` is not on your `PATH`, add it once:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## Install (development / from source)

```bash
git clone https://github.com/JabesNelma/MaubereSec-AI.git
cd MaubereSec-AI
python3 -m venv .venv
.venv/bin/pip install -e . --group dev     # runtime + test/lab tooling
.venv/bin/mauberesec --version             # expect: mauberesec 1.0.1
```

## Configure

Only an API key is required:

```bash
export OPENAI_API_KEY=<key>
```

With only the key set, the CLI defaults to provider `openai` and model
`gpt-4o-mini`. Override the model when needed:

```bash
export MSAI_MODEL=<model-id>     # optional; defaults to gpt-4o-mini
```

`MSAI_PROVIDER` is optional while only one provider is supported. If a key is
absent, the CLI stays unconfigured and commands fail with a clear message.

MCP integrations remain opt-in:

```bash
cp config/mcp.example.json ~/.config/mauberesec/mcp.json   # optional
```

Config/data paths (XDG with platform fallbacks):
- config: `$XDG_CONFIG_HOME/mauberesec/` (macOS: `~/Library/Application Support/mauberesec/config`)
- data:   `$XDG_DATA_HOME/mauberesec/`   (macOS: `~/Library/Application Support/mauberesec/data`)

## Verify the installation

```bash
mauberesec --version                        # expect: mauberesec 1.0.1
mauberesec doctor                           # environment + platform limitations
mauberesec config show                      # resolved config (no secrets)
mauberesec models test                      # credential + connectivity check
```

From a source checkout, the full release gate is:

```bash
.venv/bin/ruff check . && .venv/bin/mypy mauberesec && .venv/bin/pytest
scripts/release_check.sh                    # incl. container build
```

## Upgrade

```bash
curl -fsSL https://raw.githubusercontent.com/JabesNelma/MaubereSec-AI/v1.0.1/install.sh | sh
mauberesec doctor
```

Re-running the installer upgrades in place. To install a specific tag:

```bash
curl -fsSL https://raw.githubusercontent.com/JabesNelma/MaubereSec-AI/v1.0.1/install.sh | sh -s -- --version 1.0.1
```

Source checkouts can upgrade with `git fetch --tags && git checkout v1.0.1`
followed by `.venv/bin/pip install -e . --group dev`.

The SQLite store migrates automatically on open (`PRAGMA user_version`); no
manual migration step is required. Back up `$XDG_DATA_HOME/mauberesec/*.sqlite3`
before upgrading if you keep long-lived assessment history.

## Uninstall

```bash
.venv/bin/pip uninstall mauberesec        # remove the CLI
rm -rf ~/.config/mauberesec ~/.local/share/mauberesec   # config + history
docker image rm mauberesec/cli:1.0.1      # container image, if built
```

## Troubleshooting

| Symptom | Cause | Action |
|---|---|---|
| `doctor` reports `docker-compose FAIL` | Compose plugin not installed | Install the plugin, or use the documented `docker build`/`docker run` commands |
| `docker CLI not found` | Docker not on PATH | Install Docker; lab/scan/scanner commands require it |
| `apk dynamic` exits 3 | No hardware virtualization | Enable VT-x/AMD-V + KVM; add your user to the `kvm` group; static analysis still works |
| `models test` fails with auth error | Invalid/missing key | Set `<PROVIDER>_API_KEY`; there is no fallback provider by design |

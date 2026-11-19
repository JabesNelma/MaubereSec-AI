#!/usr/bin/env bash
# Reproducible release gate for MaubereSec AI.
# Usage: scripts/release_check.sh [--with-containers]
set -euo pipefail

cd "$(dirname "$0")/.."
PY=".venv/bin"
WITH_CONTAINERS="${1:-}"

echo "== version =="
"$PY/mauberesec" --version

echo "== lint =="
"$PY/ruff" check .
"$PY/ruff" format --check .

echo "== types =="
"$PY/mypy" mauberesec

echo "== tests (unit + security + integration) =="
"$PY/pytest" -q

echo "== CLI smoke =="
"$PY/mauberesec" --help >/dev/null
"$PY/mauberesec" doctor || true   # doctor exits 1 when optional pieces are absent

if [ "$WITH_CONTAINERS" = "--with-containers" ]; then
  echo "== container build + hardened run =="
  docker build -f docker/Dockerfile -t mauberesec/cli:1.0.0 .
  docker run --rm --read-only --cap-drop ALL --tmpfs /tmp mauberesec/cli:1.0.0 --version
  docker run --rm mauberesec/cli:1.0.0 doctor || true
  echo "== compose file syntax =="
  python3 -c "import yaml,sys; yaml.safe_load(open('docker/compose.yaml')); print('compose.yaml valid YAML')"
fi

echo "RELEASE GATE: PASS"

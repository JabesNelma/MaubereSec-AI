#!/bin/sh
# MaubereSec AI — one-command installer.
#
#   curl -fsSL https://raw.githubusercontent.com/JabesNelma/MaubereSec-AI/v1.0.1/install.sh | sh
#
# Installs into an isolated virtualenv under ~/.local/share/mauberesec and
# links the `mauberesec` command into ~/.local/bin. No sudo and no changes to
# the system Python. Re-running upgrades in place.
#
# Environment overrides:
#   MSAI_VERSION=1.0.1     release tag to install
#   MSAI_REPO=owner/repo   GitHub repository (default: JabesNelma/MaubereSec-AI)
#   MSAI_HOME=...          install root (default: ~/.local/share/mauberesec)
#   MSAI_BIN_DIR=...       command directory (default: ~/.local/bin)
#   MSAI_PYTHON=...        interpreter to use (default: newest python3 >= 3.11)
#   MSAI_INSTALL_URL=...   explicit source tarball URL (skips GitHub URL build)
#   MSAI_TARBALL_SHA256=.. optional SHA-256 of the downloaded tarball
#   MSAI_MODIFY_PATH=1     append PATH export to ~/.bashrc when missing
#
# Flags: --version X | --force | --uninstall | --help

set -eu

REPO="${MSAI_REPO:-JabesNelma/MaubereSec-AI}"
VERSION="${MSAI_VERSION:-1.0.1}"
INSTALL_ROOT="${MSAI_HOME:-$HOME/.local/share/mauberesec}"
BIN_DIR="${MSAI_BIN_DIR:-$HOME/.local/bin}"
VENV="$INSTALL_ROOT/venv"
FORCE=0
UNINSTALL=0

usage() {
  cat <<'EOF'
MaubereSec AI installer

Usage:
  install.sh [--version VERSION] [--force] [--uninstall]

  --version VERSION  Install a specific release tag (default: 1.0.1)
  --force            Reinstall even if the requested version is present
  --uninstall        Remove the CLI and its virtualenv (keeps assessment data)
  --help             Show this help

Environment:
  MSAI_HOME, MSAI_BIN_DIR, MSAI_PYTHON, MSAI_REPO,
  MSAI_INSTALL_URL, MSAI_TARBALL_SHA256, MSAI_MODIFY_PATH
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

note() {
  printf '%s\n' "$*"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      [ "$#" -ge 2 ] || die "--version requires a value"
      VERSION="$2"
      shift 2
      ;;
    --force)
      FORCE=1
      shift
      ;;
    --uninstall)
      UNINSTALL=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1 (use --help)"
      ;;
  esac
done

if [ "$UNINSTALL" = "1" ]; then
  if [ -e "$BIN_DIR/mauberesec" ] || [ -L "$BIN_DIR/mauberesec" ]; then
    rm -f "$BIN_DIR/mauberesec"
    note "Removed $BIN_DIR/mauberesec"
  fi
  if [ -d "$VENV" ]; then
    rm -rf "$VENV"
    note "Removed $VENV"
  fi
  note "Kept assessment data in $INSTALL_ROOT (delete manually to erase history)."
  exit 0
fi

case "$(uname -s 2>/dev/null || echo unknown)" in
  Linux|Darwin) ;;
  *)
    note "warning: this installer targets Linux and macOS." >&2
    note "On Windows, use WSL or: pip install \"mauberesec @ git+https://github.com/$REPO@v$VERSION\"" >&2
    ;;
esac

find_python() {
  if [ -n "${MSAI_PYTHON:-}" ]; then
    printf '%s\n' "$MSAI_PYTHON"
    return 0
  fi
  for candidate in python3.14 python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1 &&
      "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
      command -v "$candidate"
      return 0
    fi
  done
  return 1
}

PYTHON="$(find_python)" || die "Python >= 3.11 not found. Install Python 3.11+ or set MSAI_PYTHON."

if [ -x "$VENV/bin/mauberesec" ] && [ "$FORCE" = "0" ]; then
  CURRENT="$("$VENV/bin/mauberesec" --version 2>/dev/null | awk '{print $2}')" || CURRENT=""
  if [ "$CURRENT" = "$VERSION" ]; then
    note "MaubereSec AI $VERSION is already installed."
    mkdir -p "$BIN_DIR"
    ln -sfn "$VENV/bin/mauberesec" "$BIN_DIR/mauberesec"
    note "Command: $BIN_DIR/mauberesec"
    note "Run:     mauberesec doctor"
    exit 0
  fi
fi

URL="${MSAI_INSTALL_URL:-https://github.com/$REPO/archive/refs/tags/v$VERSION.tar.gz}"
TMPDIR_INSTALL="$(mktemp -d "${TMPDIR:-/tmp}/mauberesec-install.XXXXXX")"
TARBALL="$TMPDIR_INSTALL/mauberesec.tar.gz"
cleanup() {
  rm -rf "$TMPDIR_INSTALL"
}
trap cleanup EXIT INT TERM

note "Downloading MaubereSec AI $VERSION..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL --retry 3 --connect-timeout 15 -o "$TARBALL" "$URL" ||
    die "download failed: $URL (does tag v$VERSION exist?)"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$TARBALL" "$URL" || die "download failed: $URL (does tag v$VERSION exist?)"
else
  die "curl or wget is required to download the release"
fi

if [ -n "${MSAI_TARBALL_SHA256:-}" ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_SHA="$(sha256sum "$TARBALL" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    ACTUAL_SHA="$(shasum -a 256 "$TARBALL" | awk '{print $1}')"
  else
    die "MSAI_TARBALL_SHA256 set but no sha256sum/shasum available"
  fi
  [ "$ACTUAL_SHA" = "$MSAI_TARBALL_SHA256" ] ||
    die "checksum mismatch: expected $MSAI_TARBALL_SHA256, got $ACTUAL_SHA"
fi

mkdir -p "$INSTALL_ROOT" "$BIN_DIR"

if [ ! -x "$VENV/bin/python" ]; then
  note "Creating virtualenv in $VENV..."
  "$PYTHON" -m venv "$VENV" || die "failed to create virtualenv (is python3-venv installed?)"
fi

if ! "$VENV/bin/python" -m pip --version >/dev/null 2>&1; then
  note "Bootstrapping pip..."
  "$VENV/bin/python" -m ensurepip --upgrade >/dev/null 2>&1 ||
    die "pip is unavailable in the virtualenv"
fi

note "Installing MaubereSec AI $VERSION..."
if [ "$FORCE" = "1" ]; then
  "$VENV/bin/python" -m pip install --quiet --disable-pip-version-check \
    --force-reinstall "$TARBALL"
else
  "$VENV/bin/python" -m pip install --quiet --disable-pip-version-check \
    --upgrade "$TARBALL"
fi

INSTALLED="$("$VENV/bin/mauberesec" --version 2>/dev/null | awk '{print $2}')" || INSTALLED=""
[ "$INSTALLED" = "$VERSION" ] ||
  die "installation reported version '$INSTALLED', expected '$VERSION'"

ln -sfn "$VENV/bin/mauberesec" "$BIN_DIR/mauberesec"

note ""
note "MaubereSec AI $VERSION installed."
note "Command: $BIN_DIR/mauberesec"

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    note ""
    note "Note: $BIN_DIR is not on your PATH."
    note "Add it for this shell:  export PATH=\"$BIN_DIR:\$PATH\""
    if [ "${MSAI_MODIFY_PATH:-0}" = "1" ]; then
      for rc in "$HOME/.bashrc" "$HOME/.profile" "$HOME/.zshrc"; do
        [ -f "$rc" ] || continue
        if ! grep -q "MaubereSec AI installer" "$rc" 2>/dev/null; then
          printf '\n# MaubereSec AI installer\nexport PATH="%s:$PATH"\n' "$BIN_DIR" >>"$rc"
          note "Updated $rc"
        fi
      done
    else
      note "Or re-run with MSAI_MODIFY_PATH=1 to add it to your shell profile."
    fi
    ;;
esac

note ""
note "Next steps:"
note "  export OPENAI_API_KEY=\"sk-...\""
note "  mauberesec doctor"
note "  mauberesec models test"
note ""
note "No MSAI_PROVIDER or MSAI_MODEL is required: when only OPENAI_API_KEY is"
note "set, the CLI defaults to provider=openai and model=gpt-4o-mini. Override"
note "either variable if your account or preferred model differs."

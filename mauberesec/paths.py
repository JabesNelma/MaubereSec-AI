"""XDG-style config and data paths with cross-platform fallbacks.

- Linux: $XDG_CONFIG_HOME/mauberesec, $XDG_DATA_HOME/mauberesec
- macOS: ~/Library/Application Support/mauberesec, ...
- Windows: %LOCALAPPDATA%/mauberesec, ...

Paths are resolved from the environment at call time so tests can
redirect them.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "mauberesec"


def _is_darwin() -> bool:
    return sys.platform == "darwin"


def _is_windows() -> bool:
    return sys.platform.startswith("win")


def config_dir(env: dict[str, str] | None = None) -> Path:
    """Directory for configuration files (created on demand by callers)."""
    env_map: dict[str, str] = dict(os.environ) if env is None else dict(env)
    xdg = env_map.get("XDG_CONFIG_HOME", "").strip()
    if xdg:
        return Path(xdg) / APP_NAME
    home = Path.home()
    if _is_darwin():
        return home / "Library" / "Application Support" / APP_NAME / "config"
    if _is_windows():
        base = env_map.get("LOCALAPPDATA", str(home / "AppData" / "Local"))
        return Path(base) / APP_NAME / "config"
    return home / ".config" / APP_NAME


def data_dir(env: dict[str, str] | None = None) -> Path:
    """Directory for persistent application data (database, history)."""
    env_map: dict[str, str] = dict(os.environ) if env is None else dict(env)
    xdg = env_map.get("XDG_DATA_HOME", "").strip()
    if xdg:
        return Path(xdg) / APP_NAME
    home = Path.home()
    if _is_darwin():
        return home / "Library" / "Application Support" / APP_NAME / "data"
    if _is_windows():
        base = env_map.get("LOCALAPPDATA", str(home / "AppData" / "Local"))
        return Path(base) / APP_NAME / "data"
    return home / ".local" / "share" / APP_NAME


def database_path(env: dict[str, str] | None = None) -> Path:
    """Default SQLite database location."""
    return data_dir(env) / "mauberesec.sqlite3"


def ensure_data_dir(env: dict[str, str] | None = None) -> Path:
    """Create and return the data directory."""
    path = data_dir(env)
    path.mkdir(parents=True, exist_ok=True)
    return path

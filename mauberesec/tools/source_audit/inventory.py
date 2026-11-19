"""File inventory with exclusions and hard limits (CODE-003).

The inventory feeds model context and summary output — never the scanners
directly. Binaries, generated trees, and oversized files are excluded;
secret-looking files are excluded from any cloud-bound context but still
scanned locally by containerized tools.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from ...scope.pathcheck import is_within, safe_resolve

DEFAULT_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "__pycache__",
        "node_modules",
        "venv",
        ".venv",
        "dist",
        "build",
        "target",
        "vendor",
        ".idea",
        ".vscode",
    }
)
SECRET_FILE_HINTS = frozenset(
    {".env", ".env.local", ".env.production", "credentials.json", "secrets.yaml"}
)


class InventoryLimitError(Exception):
    """Repository exceeds safe inventory limits."""


@dataclass
class Inventory:
    root: Path
    files: list[str] = field(default_factory=list)
    skipped_symlinks: list[str] = field(default_factory=list)
    excluded_count: int = 0
    total_bytes: int = 0
    secret_hint_files: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"Inventory of {self.root}: {len(self.files)} files, "
            f"{self.total_bytes} bytes, {self.excluded_count} excluded entries, "
            f"{len(self.skipped_symlinks)} escaping symlinks skipped."
        )


def build_inventory(
    root: Path,
    *,
    max_files: int = 20_000,
    max_total_bytes: int = 512 * 1024 * 1024,
    max_file_bytes: int = 8 * 1024 * 1024,
    excluded_dirs: frozenset[str] = DEFAULT_EXCLUDED_DIRS,
) -> Inventory:
    """Walk *root* and build a bounded, symlink-safe inventory."""
    inventory = Inventory(root=root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        # Prune excluded/generated directories in place.
        keep = [d for d in dirnames if d not in excluded_dirs]
        inventory.excluded_count += len(dirnames) - len(keep)
        dirnames[:] = keep

        for name in filenames:
            entry = current / name
            resolved = safe_resolve(root, entry)
            if resolved is None:
                if entry.is_symlink():
                    inventory.skipped_symlinks.append(str(entry.relative_to(root)))
                continue
            if not resolved.is_file() or not is_within(root, resolved):
                continue
            try:
                size = resolved.stat().st_size
            except OSError:
                continue
            rel = str(resolved.relative_to(root))
            if name in SECRET_FILE_HINTS:
                inventory.secret_hint_files.append(rel)
            if size > max_file_bytes:
                inventory.excluded_count += 1
                continue
            inventory.total_bytes += size
            if len(inventory.files) >= max_files:
                raise InventoryLimitError(f"Repository exceeds max_files={max_files}.")
            if inventory.total_bytes > max_total_bytes:
                raise InventoryLimitError(f"Repository exceeds max_total_bytes={max_total_bytes}.")
            if not _looks_binary(resolved):
                inventory.files.append(rel)
    return inventory


def _looks_binary(path: Path, sample: int = 1024) -> bool:
    try:
        with open(path, "rb") as handle:
            return b"\x00" in handle.read(sample)
    except OSError:
        return True

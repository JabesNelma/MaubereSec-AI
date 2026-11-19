"""Repository path selection, canonicalization, and traversal protection.

Rules (PRD CODE-001/CODE-002):
- The audit root must be an existing local directory.
- Every inventoried file must resolve (after symlinks) inside the root.
- Symlinked roots are rejected; symlinks escaping the root are skipped and
  reported, never followed out of the tree.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


class PathError_(Exception):
    """Invalid or unsafe path selection."""


@dataclass(frozen=True)
class CanonicalPath:
    root: Path

    def __str__(self) -> str:
        return str(self.root)


def canonicalize_repo_path(raw: str) -> CanonicalPath:
    """Canonicalize the user-selected repository root."""
    if not raw or "\x00" in raw:
        raise PathError_("Empty or NUL-containing path.")
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    # Reject symlinked roots explicitly (resolve() would silently follow).
    if candidate.is_symlink():
        raise PathError_(f"Repository root must not be a symlink: {candidate}")
    if not candidate.is_dir():
        raise PathError_(f"Repository root is not a directory: {candidate}")
    return CanonicalPath(root=candidate.resolve(strict=True))


def is_within(root: Path, target: Path) -> bool:
    """True when *target* (already resolved) stays inside *root*."""
    try:
        target.relative_to(root)
    except ValueError:
        return False
    return True


def safe_resolve(root: Path, entry: Path) -> Path | None:
    """Resolve *entry* inside *root*; None if it escapes via symlink."""
    try:
        resolved = entry.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    return resolved if is_within(root, resolved) else None

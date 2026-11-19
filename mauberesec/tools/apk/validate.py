"""Host-side APK validation: path, size, magic, SHA-256 (no execution)."""

from __future__ import annotations

import hashlib
import zipfile
from dataclasses import dataclass
from pathlib import Path

MAX_APK_BYTES = 500 * 1024 * 1024
ZIP_MAGIC = b"PK\x03\x04"


class ApkValidationError(Exception):
    """The file is not a safely analyzable APK."""


@dataclass(frozen=True)
class ApkFile:
    path: Path
    sha256: str
    size_bytes: int


def validate_apk_path(raw: str) -> ApkFile:
    if not raw or "\x00" in raw:
        raise ApkValidationError("Empty or NUL-containing path.")
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    if path.is_symlink():
        raise ApkValidationError(f"APK path must not be a symlink: {path}")
    if not path.is_file():
        raise ApkValidationError(f"APK path is not a file: {path}")
    size = path.stat().st_size
    if size == 0:
        raise ApkValidationError("APK file is empty.")
    if size > MAX_APK_BYTES:
        raise ApkValidationError(f"APK exceeds the size cap ({size} > {MAX_APK_BYTES} bytes).")
    with open(path, "rb") as handle:
        magic = handle.read(4)
    if magic != ZIP_MAGIC:
        raise ApkValidationError("File does not start with a ZIP header (PK..).")
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return ApkFile(path=path.resolve(), sha256=digest.hexdigest(), size_bytes=size)


def quick_zip_probe(path: Path) -> None:
    """Cheap structural check so obviously malformed files fail before Docker."""
    try:
        with zipfile.ZipFile(path) as zf:
            if zf.testzip() is not None:
                raise ApkValidationError("ZIP central directory reports a bad entry.")
    except zipfile.BadZipFile as exc:
        raise ApkValidationError(f"Malformed ZIP/APK: {exc}") from exc

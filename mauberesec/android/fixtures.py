"""Synthetic accounts and data for dynamic analysis (v0.9).

Roadmap requires synthetic accounts/data only. Everything here is fixed,
deterministic, and clearly fake; nothing is derived from real users, and
no real credentials are ever supplied to the emulator.
"""

from __future__ import annotations

import json
from pathlib import Path

SYNTHETIC_ACCOUNT = {
    "username": "msai-dyn-user",
    "password": "msai-dyn-pass-4b21",
    "email": "msai-dyn-user@example.invalid",
    "display_name": "MSAI Synthetic User",
}

SYNTHETIC_FILES: tuple[tuple[str, str], ...] = (
    (
        "seed_account.json",
        json.dumps(SYNTHETIC_ACCOUNT, indent=2) + "\n",
    ),
    (
        "notes.txt",
        "MSAI synthetic fixture: no real data. Safe to delete.\n",
    ),
)

SYNTHETIC_REMARKER = "MSAI-SYNTHETIC-DATASET"


def write_synthetic_dataset(target_dir: Path) -> list[str]:
    """Materialize the synthetic dataset; returns the written file names."""
    target_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for name, content in SYNTHETIC_FILES:
        (target_dir / name).write_text(content, encoding="utf-8")
        written.append(name)
    (target_dir / "DATASET_MARKER").write_text(SYNTHETIC_REMARKER + "\n", encoding="utf-8")
    written.append("DATASET_MARKER")
    return written


def dataset_marker() -> str:
    return SYNTHETIC_REMARKER

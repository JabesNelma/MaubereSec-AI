"""Dependency manifest analysis (CODE-006, no dependency installation).

Reads manifest/lock files from the already-inventoried tree and produces a
summary only. No project code is executed and no packages are installed.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

_REQUIREMENT_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([^ \t;#]+)")


@dataclass
class ManifestSummary:
    ecosystem: str
    path: str
    packages: list[tuple[str, str]]  # (name, version-or-"*")

    def render(self) -> str:
        capped = ", ".join(f"{n}=={v}" for n, v in self.packages[:50])
        more = "" if len(self.packages) <= 50 else f" (+{len(self.packages) - 50} more)"
        return f"{self.ecosystem} [{self.path}] {len(self.packages)} deps: {capped}{more}"


def analyze_manifests(root: Path) -> list[ManifestSummary]:
    summaries: list[ManifestSummary] = []

    requirements = root / "requirements.txt"
    if requirements.is_file():
        packages = []
        for line in requirements.read_text(errors="replace").splitlines():
            match = _REQUIREMENT_RE.match(line)
            if match:
                packages.append((match.group(1), match.group(2)))
            elif line.strip() and not line.lstrip().startswith(("#", "-")):
                name = line.split(";")[0].split("==")[0].strip()
                if name:
                    packages.append((name, "*"))
        summaries.append(ManifestSummary("python", "requirements.txt", packages))

    package_json = root / "package.json"
    if package_json.is_file():
        try:
            data = json.loads(package_json.read_text(errors="replace"))
        except json.JSONDecodeError:
            data = {}
        packages = [
            (name, spec if re.fullmatch(r"[\d.]+", str(spec)) else "*")
            for section in ("dependencies", "devDependencies")
            for name, spec in (data.get(section) or {}).items()
        ]
        summaries.append(ManifestSummary("node", "package.json", packages))

    go_mod = root / "go.mod"
    if go_mod.is_file():
        packages = []
        for line in go_mod.read_text(errors="replace").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] not in ("require", "module") and "/" in parts[0]:
                packages.append((parts[0], parts[1]))
        summaries.append(ManifestSummary("go", "go.mod", packages))

    return summaries

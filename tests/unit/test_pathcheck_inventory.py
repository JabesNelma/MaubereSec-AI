"""Unit tests for path safety, inventory, and manifest analysis."""

import os

import pytest

from mauberesec.scope.pathcheck import PathError_, canonicalize_repo_path, safe_resolve
from mauberesec.tools.source_audit.inventory import (
    InventoryLimitError,
    build_inventory,
)
from mauberesec.tools.source_audit.manifest import analyze_manifests


@pytest.fixture()
def repo(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('hi')\n")
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "x.js").write_text("x")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref")
    (tmp_path / "binary.bin").write_bytes(b"\x00\x01\x02")
    (tmp_path / "big.txt").write_bytes(b"a" * (8 * 1024 * 1024 + 100))
    (tmp_path / ".env").write_text("API_KEY=abc\n")
    return tmp_path


def test_canonicalize_requires_dir(tmp_path):
    with pytest.raises(PathError_):
        canonicalize_repo_path(str(tmp_path / "missing"))


def test_canonicalize_rejects_symlink_root(repo):
    link = repo.parent / "repo-link"
    if link.exists() or link.is_symlink():
        link.unlink()
    os.symlink(repo, link)
    with pytest.raises(PathError_, match="symlink"):
        canonicalize_repo_path(str(link))
    link.unlink()


def test_canonicalize_resolves_relative(repo, monkeypatch):
    monkeypatch.chdir(repo.parent)
    canonical = canonicalize_repo_path(str(repo.name))
    assert canonical.root == repo.resolve()


def test_safe_resolve_blocks_escape(repo):
    outside = repo.parent / "outside.txt"
    outside.write_text("x")
    link = repo / "escape.txt"
    os.symlink(outside, link)
    assert safe_resolve(repo.resolve(), link) is None
    link.unlink()
    outside.unlink()


def test_inventory_excludes_generated_and_oversized(repo):
    inventory = build_inventory(repo)
    names = inventory.files
    assert "src/app.py" in names
    assert not any(n.startswith("node_modules") for n in names)
    assert not any(n.startswith(".git") for n in names)
    assert "binary.bin" not in names  # binary excluded
    assert "big.txt" not in names  # oversized excluded
    assert ".env" in inventory.secret_hint_files


def test_inventory_skips_escaping_symlinks(repo):
    outside = repo.parent / "secret-outside.txt"
    outside.write_text("s")
    link = repo / "leak"
    os.symlink(outside, link)
    inventory = build_inventory(repo)
    assert inventory.skipped_symlinks == ["leak"]
    link.unlink()
    outside.unlink()


def test_inventory_limit_files(repo):
    with pytest.raises(InventoryLimitError, match="max_files"):
        build_inventory(repo, max_files=1)


def test_manifest_analysis(repo):
    (repo / "requirements.txt").write_text("# comment\nrequests==2.31.0\nflask\n")
    (repo / "package.json").write_text(
        '{"dependencies": {"lodash": "4.17.21"}, "devDependencies": {"jest": "^29"}}'
    )
    (repo / "go.mod").write_text(
        "module x\n\ngo 1.22\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n)\n"
    )
    summaries = analyze_manifests(repo)
    by_eco = {s.ecosystem: s for s in summaries}
    assert ("requests", "2.31.0") in by_eco["python"].packages
    assert ("flask", "*") in by_eco["python"].packages
    assert ("lodash", "4.17.21") in by_eco["node"].packages
    assert ("jest", "*") in by_eco["node"].packages
    assert ("github.com/gin-gonic/gin", "v1.9.1") in by_eco["go"].packages

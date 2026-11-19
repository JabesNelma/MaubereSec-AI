"""Integration tests: scanner container isolation against the real Docker daemon.

Proves the v0.5 acceptance criteria:
- The source mount inside the scanner container is read-only (writes fail).
- The scanner container has no network (network=none).
- Fixed adapter plumbing produces parseable findings from stdout.
"""

import json
import shutil

import pytest

from mauberesec.docker.client import DockerClient
from mauberesec.tools.source_audit.adapters import (
    AdapterSpec,
    DockerScannerAdapter,
    parse_gitleaks,
)

pytestmark = pytest.mark.integration

docker_path = shutil.which("docker")


@pytest.fixture(scope="module")
def client():
    if docker_path is None:
        pytest.skip("docker CLI not available")
    c = DockerClient(docker_path=docker_path)
    if c.daemon_version() is None:
        pytest.skip("docker daemon not reachable")
    return c


ALPINE = "alpine:3.20"


def _make_world_traversable(path):
    """Scanner containers run with no capabilities (no DAC_OVERRIDE), so every
    parent of the bind source must be traversable."""
    import os

    for part in [path, *path.parents]:
        if part.name == "tmp":
            break
        try:
            os.chmod(part, 0o755)  # noqa: S103 - test fixture traversal only
        except OSError:
            break


def test_scanner_cannot_write_source_mount(client, tmp_path):
    _make_world_traversable(tmp_path)
    (tmp_path / "file.txt").write_text("data")
    result = client.run_scanner(
        ALPINE, ["sh", "-c", "echo hacked > /src/evil.txt"], host_path=str(tmp_path)
    )
    assert result.returncode != 0
    assert "permission denied" in result.stderr.lower() or "read-only" in result.stderr.lower()
    assert not (tmp_path / "evil.txt").exists()
    assert (tmp_path / "file.txt").read_text() == "data"


def test_scanner_has_no_network(client, tmp_path):
    _make_world_traversable(tmp_path)
    result = client.run_scanner(
        ALPINE,
        ["sh", "-c", "cat /proc/net/dev | wc -l"],
        host_path=str(tmp_path),
    )
    assert result.returncode == 0
    # With network=none only the loopback interface exists.
    result2 = client.run_scanner(
        ALPINE,
        ["sh", "-c", "ip -o link show | grep -v ' lo' | wc -l"],
        host_path=str(tmp_path),
    )
    assert result2.stdout.strip().endswith("0")


def test_scanner_reads_mounted_files(client, tmp_path):
    _make_world_traversable(tmp_path)
    (tmp_path / "gitleaks.json").write_text(
        json.dumps([{"RuleID": "test-rule", "File": "a.py", "StartLine": 1}])
    )
    spec = AdapterSpec(
        name="static.fake_scanner",
        image=ALPINE,
        command=("cat", "/src/gitleaks.json"),
    )
    adapter = DockerScannerAdapter(spec, client, parse_gitleaks)
    findings = adapter.run(str(tmp_path))
    assert len(findings) == 1
    assert findings[0].title.startswith("Possible secret")
    assert "a.py:1" in findings[0].evidence

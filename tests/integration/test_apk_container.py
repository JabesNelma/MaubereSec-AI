"""Integration tests: APK analyzer runs inside the real restricted container."""

import json
import shutil
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))
from helpers_axml import sample_manifest_axml

from mauberesec.docker.client import DockerClient
from mauberesec.tools.apk.analysis import ApkAnalyzerAdapter
from mauberesec.tools.apk.validate import validate_apk_path

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


def build_apk(tmp_path: Path, name: str = "sample.apk") -> Path:
    apk = tmp_path / name
    with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", sample_manifest_axml())
        zf.writestr(
            "classes.dex",
            b"dex\n035\nLcom/a/B;\nAKIAIOSFODNN7EXAMPLE\nLcom/c/D;\n",
        )
        zf.writestr("assets/creds.properties", b"api_key = supersecretvalue99\n")
    return apk


def test_analyzer_container_end_to_end(client, tmp_path):
    apk = build_apk(tmp_path)
    _validated = validate_apk_path(str(apk))
    report, findings = ApkAnalyzerAdapter(client).run(str(apk), _validated.sha256)

    assert report["manifest"]["package"] == "com.example.vuln"
    rules = [f.rule_name if hasattr(f, "rule_name") else f.title for f in findings]
    blob = json.dumps(report) + "\n".join(f.model_dump_json() for f in findings)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    assert "supersecretvalue99" not in blob
    assert any("debuggable" in r for r in rules)
    assert any("CAMERA" in r for r in rules)
    assert any("secret" in r.lower() for r in rules)
    assert all(f.tool_name == "apk.static_review" for f in findings)


def test_analyzer_rejects_corrupt_apk_in_container(client, tmp_path):
    bad = tmp_path / "bad.apk"
    bad.write_bytes(b"PK\x03\x04" + b"\x00" * 200)
    with pytest.raises(Exception, match=r"failed|Malformed|error"):
        ApkAnalyzerAdapter(client).run(str(bad), "0" * 64)


def test_apk_never_executed_only_read(client, tmp_path):
    """The container command is fixed: python3 analyzer <apk> — no exec of APK."""
    apk = build_apk(tmp_path, name="exec_check.apk")
    adapter = ApkAnalyzerAdapter(client)
    # Adapter command is a fixed constant containing only python3 + script.
    import inspect

    src = inspect.getsource(ApkAnalyzerAdapter.run)
    assert '["python3", "/analyzer/apk_analyzer.py"' in src
    report, _ = adapter.run(str(apk), "0" * 64)
    assert "manifest" in report

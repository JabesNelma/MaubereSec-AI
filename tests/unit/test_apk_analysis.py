"""Unit tests for AXML parsing, APK analysis logic, and zip-bomb limits."""

import zipfile
from pathlib import Path

import pytest

from mauberesec.tools.apk.container.apk_analyzer import (
    ApkAnalysisError,
    analyze_apk,
    manifest_findings,
    open_safe_zip,
    secret_findings,
)
from mauberesec.tools.apk.container.axml import parse_axml
from mauberesec.tools.apk.validate import (
    ApkValidationError,
    quick_zip_probe,
    validate_apk_path,
)
from tests.helpers_axml import clean_manifest_axml, sample_manifest_axml


def write_apk(tmp_path: Path, entries: dict[str, bytes], name: str = "app.apk") -> Path:
    apk = tmp_path / name
    with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as zf:
        for arcname, data in entries.items():
            zf.writestr(arcname, data)
    return apk


def sample_apk(tmp_path: Path) -> Path:
    return write_apk(
        tmp_path,
        {
            "AndroidManifest.xml": sample_manifest_axml(),
            # Printable runs are bounded by newlines so \b word boundaries
            # behave like real DEX strings.
            "classes.dex": b"dex\n035\n"
            + b"Lcom/example/Foo;\nLcom/example/Bar;\n"
            + b"AKIAIOSFODNN7EXAMPLE\n"
            + b"Lcom/example/Baz;\n",
            "assets/config.properties": b"password = hunter2hunter2\n",
        },
    )


def test_parse_axml_attributes():
    root = parse_axml(sample_manifest_axml())
    assert root["name"] == "manifest"
    assert root.get_attr("package") == "com.example.vuln"
    app = root.find_all("application")[0]
    assert app.get_attr("debuggable") is True
    assert app.get_attr("usesCleartextTraffic") is True


def test_manifest_findings_coverage():
    root = parse_axml(sample_manifest_axml())
    rules = {f["rule"]: f for f in manifest_findings(root)}
    assert "manifest.debuggable" in rules
    assert "manifest.cleartext" in rules
    assert "manifest.dangerous_permission" in rules
    assert "manifest.exported_component" in rules
    assert "manifest.outdated_target_sdk" in rules
    assert rules["manifest.exported_component"]["severity"] == "medium"
    assert "CAMERA" in rules["manifest.dangerous_permission"]["title"]


def test_analyze_apk_finds_secret_without_value(tmp_path):
    apk = sample_apk(tmp_path)
    report = analyze_apk(str(apk), sha256="deadbeef")
    assert report["manifest"]["package"] == "com.example.vuln"
    blob = str(report)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob  # secret value never reported
    assert "hunter2hunter2" not in blob
    rules = [f["rule"] for f in report["findings"]]
    assert "secret.aws-access-key" in rules
    assert "secret.password-assignment" in rules
    evidence = [f["evidence"] for f in report["findings"]]
    assert any("value withheld" in e for e in evidence)


def test_analyze_apk_clean(tmp_path):
    entries = {
        "AndroidManifest.xml": clean_manifest_axml(),
        "assets/readme.txt": b"hello world\n",
    }
    apk = write_apk(tmp_path, entries, name="clean.apk")
    report = analyze_apk(str(apk))
    assert report["findings"] == []


def test_zip_bomb_ratio_rejected(tmp_path):
    # Highly compressible large payload: ratio far beyond MAX_RATIO.
    bomb = write_apk(
        tmp_path,
        {
            "AndroidManifest.xml": sample_manifest_axml(),
            "assets/big.bin": b"\x00" * (8 * 1024 * 1024),
        },
        name="bomb.apk",
    )
    with pytest.raises(ApkAnalysisError, match=r"ratio|bomb"):
        analyze_apk(str(bomb))


def test_zip_too_many_entries(tmp_path):
    entries = {f"f{i}.txt": b"x" for i in range(30)}
    entries["AndroidManifest.xml"] = sample_manifest_axml()
    apk = write_apk(tmp_path, entries, name="many.apk")

    import mauberesec.tools.apk.container.apk_analyzer as az

    original = az.MAX_ENTRIES
    az.MAX_ENTRIES = 10
    try:
        with pytest.raises(ApkAnalysisError, match="Too many entries"):
            analyze_apk(str(apk))
    finally:
        az.MAX_ENTRIES = original


def test_malformed_zip_fails_safely(tmp_path):
    bad = tmp_path / "bad.apk"
    bad.write_bytes(b"PK\x03\x04" + b"\x00" * 64)
    with pytest.raises(ApkAnalysisError):
        analyze_apk(str(bad))
    with pytest.raises(ApkValidationError):
        quick_zip_probe(bad)


def test_missing_manifest_rejected(tmp_path):
    apk = write_apk(tmp_path, {"other.xml": b"<x/>"}, name="nomanifest.apk")
    with pytest.raises(ApkAnalysisError, match="AndroidManifest"):
        analyze_apk(str(apk))


def test_validate_apk_path(tmp_path):
    apk = sample_apk(tmp_path)
    info = validate_apk_path(str(apk))
    assert len(info.sha256) == 64
    assert info.path == apk.resolve()

    with pytest.raises(ApkValidationError, match="not a file"):
        validate_apk_path(str(tmp_path / "missing.apk"))

    fake = tmp_path / "fake.apk"
    fake.write_bytes(b"MZ\x90\x00" + b"\x00" * 32)
    with pytest.raises(ApkValidationError, match="ZIP header"):
        validate_apk_path(str(fake))


def test_open_safe_zip_entry_cap(tmp_path):
    apk = write_apk(
        tmp_path,
        {"AndroidManifest.xml": sample_manifest_axml(), "assets/huge.bin": b"a"},
        name="cap.apk",
    )
    import mauberesec.tools.apk.container.apk_analyzer as az

    original = az.MAX_ENTRY_UNCOMPRESSED
    az.MAX_ENTRY_UNCOMPRESSED = 0
    try:
        with pytest.raises(ApkAnalysisError, match="per-entry cap"):
            open_safe_zip(str(apk))
    finally:
        az.MAX_ENTRY_UNCOMPRESSED = original


def test_secret_findings_dex_and_assets(tmp_path):
    apk = sample_apk(tmp_path)
    with zipfile.ZipFile(apk) as zf:
        findings = secret_findings(zf)
    rules = [f["rule"] for f in findings]
    assert "secret.aws-access-key" in rules
    artifacts = [f["artifact"] for f in findings]
    assert any(a.startswith("classes.dex@") for a in artifacts)

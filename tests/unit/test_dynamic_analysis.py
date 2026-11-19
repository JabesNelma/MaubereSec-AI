"""Unit + security tests for v0.9 dynamic analysis prerequisites."""

import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parents[1]))

from mauberesec.android.emulator import EmulatorRunError, EmulatorSpec
from mauberesec.android.fixtures import (
    SYNTHETIC_ACCOUNT,
    dataset_marker,
    write_synthetic_dataset,
)
from mauberesec.android.hostcheck import (
    EmulatorUnsupportedError,
    HostCapability,
    detect_host,
    require_emulator_support,
)
from mauberesec.cli.app import app

runner = CliRunner()


def cap(supported: bool = True) -> HostCapability:
    return HostCapability(
        kvm_present=supported,
        kvm_accessible=supported,
        cpu_virtualization=supported,
        docker_available=supported,
        reasons=() if supported else ("/dev/kvm not present",),
    )


# --- host capability detection -------------------------------------------------


def test_detect_host_missing_kvm(tmp_path):
    result = detect_host(kvm_device=tmp_path / "kvm", cpuinfo=tmp_path / "cpuinfo")
    assert result.emulator_supported is False
    assert any("not present" in r for r in result.reasons)


def test_detect_host_no_virtualization_flags(tmp_path):
    kvm = tmp_path / "kvm"
    kvm.write_text("")
    cpuinfo = tmp_path / "cpuinfo"
    cpuinfo.write_text("model name: generic\n")
    result = detect_host(kvm_device=kvm, cpuinfo=cpuinfo)
    assert result.kvm_present is True
    assert result.cpu_virtualization is False
    assert result.emulator_supported is False


def test_require_support_raises_with_guidance():
    with pytest.raises(EmulatorUnsupportedError) as exc:
        require_emulator_support(cap(False))
    message = str(exc.value)
    assert "Refusing to run rather than degrading isolation" in message
    assert "kvm" in message
    assert "mauberesec apk analyze" in message  # points at the safe alternative


def test_require_support_passes_when_supported():
    require_emulator_support(cap(True))


# --- synthetic fixtures --------------------------------------------------------


def test_synthetic_dataset_is_marked(tmp_path):
    written = write_synthetic_dataset(tmp_path / "ds")
    assert "DATASET_MARKER" in written
    assert dataset_marker() in (tmp_path / "ds" / "DATASET_MARKER").read_text()
    assert SYNTHETIC_ACCOUNT["email"].endswith(".invalid")
    assert "real" not in SYNTHETIC_ACCOUNT["password"]


def test_fixtures_contain_no_realistic_secrets():
    from mauberesec.android import fixtures

    blob = (Path(fixtures.__file__).read_text()).lower()
    for marker in ("akia", "sk-proj", "ghp_", "aiza"):
        assert marker not in blob


# --- CLI refusal paths ---------------------------------------------------------


def make_apk(tmp_path: Path) -> Path:
    import zipfile

    from tests.helpers_axml import sample_manifest_axml

    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", sample_manifest_axml())
    return apk


def test_cli_dynamic_refuses_unsupported_host(tmp_path, monkeypatch):
    from mauberesec.cli import apk as apk_cli

    monkeypatch.setattr(apk_cli, "detect_host", lambda: cap(False))
    result = runner.invoke(app, ["apk", "dynamic", str(make_apk(tmp_path))])
    assert result.exit_code == 3
    assert "Refusing to run" in (result.output + (result.stderr or ""))


def test_cli_dynamic_dry_run_on_supported_host(tmp_path, monkeypatch):
    from mauberesec.cli import apk as apk_cli

    monkeypatch.setattr(apk_cli, "detect_host", lambda: cap(True))
    result = runner.invoke(app, ["apk", "dynamic", str(make_apk(tmp_path)), "--dry-run"])
    assert result.exit_code == 0
    assert "EXPERIMENTAL" in result.output
    assert "dry-run: nothing executed" in result.output
    assert "internal" in result.output


def test_cli_dynamic_requires_package_when_unknown(tmp_path, monkeypatch):
    from mauberesec.cli import apk as apk_cli

    monkeypatch.setattr(apk_cli, "detect_host", lambda: cap(True))
    monkeypatch.setattr(apk_cli, "_guess_package", lambda p: "")
    result = runner.invoke(app, ["apk", "dynamic", str(make_apk(tmp_path))])
    assert result.exit_code == 2
    assert "--package" in result.output


def test_emulator_spec_requires_existing_apk():
    spec = EmulatorSpec(apk_path=Path("/nonexistent/app.apk"), package="com.x")
    assert spec.logcat_seconds == 20
    assert spec.apk_path.is_file() is False
    # Runner raises before any docker interaction.
    from mauberesec.android.emulator import EmulatorRunner
    from mauberesec.docker.client import DockerClient

    with pytest.raises(EmulatorRunError, match="APK not found"):
        EmulatorRunner(DockerClient(docker_path="")).run(spec, cap(True))

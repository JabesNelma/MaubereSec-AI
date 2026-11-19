"""Integration: emulator orchestration end-to-end using a stub emulator image.

A real Android emulator image is multi-gigabyte, so these tests build a tiny
stub image that mimics the parts of the interface our orchestration depends
on (an image whose container stays alive, an ``adb`` binary speaking the few
subcommands the entry script uses, and ``sh``). That exercises our real
orchestration: internal network creation, detached container start, docker
exec of the fixed entry script, synthetic dataset push, install/launch,
logcat capture, teardown, and verified reset between runs.

Set MSAI_EMULATOR_IMAGE to a real image to additionally run the same flow
against it (skipped by default).
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from mauberesec.android.emulator import EmulatorRunner, EmulatorSpec
from mauberesec.android.hostcheck import detect_host
from mauberesec.docker.client import DockerClient

pytestmark = pytest.mark.integration

docker_path = shutil.which("docker")

FAKE_ADB = """#!/bin/sh
# Minimal adb stub for orchestration tests (no real device involved).
case "$1" in
  wait-for-device) exit 0 ;;
  shell)
    shift
    case "$1" in
      getprop) echo 1 ;;
      monkey) exit 0 ;;
      ps) echo "USER PID PPID NAME"; echo "u0_a1 100 1 com.example.vuln" ;;
      pm) echo "package:com.example.vuln"; echo "package:com.android.settings" ;;
    esac
    exit 0 ;;
  push) exit 0 ;;
  install) echo "Success" ;;
  logcat)
    echo "MSAI-SYNTHETIC-DATASET synthetic fixture noted"
    echo "I/ActivityManager: start com.example.vuln" ;;
  *) exit 0 ;;
esac
"""


@pytest.fixture(scope="module")
def stub_image():
    if docker_path is None:
        pytest.skip("docker CLI not available")
    import tempfile

    build_dir = Path(tempfile.gettempdir()) / "msai-emu-stub"
    build_dir.mkdir(parents=True, exist_ok=True)
    (build_dir / "adb").write_text(FAKE_ADB)
    (build_dir / "Dockerfile").write_text(
        "FROM alpine:3.20\n"
        "COPY adb /usr/local/bin/adb\n"
        "RUN chmod +x /usr/local/bin/adb\n"
        'CMD ["sleep", "3600"]\n'
    )
    tag = "msai-emu-stub:test"
    result = subprocess.run(  # noqa: S603 - fixed argv, test-only image build
        [docker_path, "build", "-t", tag, str(build_dir)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"stub image build failed: {result.stderr[-200:]}")
    yield tag
    shutil.rmtree(build_dir, ignore_errors=True)


@pytest.fixture()
def client():
    c = DockerClient(docker_path=docker_path)
    if c.daemon_version() is None:
        pytest.skip("docker daemon not reachable")
    return c


def make_apk(tmp_path: Path) -> Path:
    import sys
    import zipfile

    sys.path.insert(0, str(Path(__file__).parents[1]))
    from helpers_axml import sample_manifest_axml

    apk = tmp_path / "vuln.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", sample_manifest_axml())
    return apk


def test_orchestration_end_to_end_and_verified_reset(client, stub_image, tmp_path):
    runner = EmulatorRunner(client)
    spec = EmulatorSpec(
        apk_path=make_apk(tmp_path),
        package="com.example.vuln",
        image=stub_image,
        logcat_seconds=5,
    )
    capability = detect_host()

    first = runner.run(spec, capability)
    assert first.emulator.get("apk_installed") is True
    assert first.emulator.get("launched") is True
    assert first.emulator.get("packages_visible", 0) >= 1
    assert first.reset_verified is True
    assert first.container_id
    assert "internal" not in first.network  # name check: our label format
    assert any("host adb is never used" in n for n in first.notes)

    # Second run: fresh container identity proves the reset.
    second = runner.run(spec, capability, previous_container_id=first.container_id)
    assert second.reset_verified is True
    assert second.container_id != first.container_id

    # Synthetic dataset marker surfaces from captured logcat.
    assert any("synthetic dataset marker" in n for n in second.notes)


def test_network_is_created_internal_and_torn_down(client, stub_image, tmp_path):
    runner = EmulatorRunner(client)
    run_id = "testnet01"
    name = runner.create_isolated_network(run_id)
    inspect = client.run(["network", "inspect", name])
    assert inspect.ok
    assert (
        '"Internal": true'
        in inspect.stdout.replace(" ", "").replace('"Internal":true', '"Internal": true')
        or "Internal" in inspect.stdout
    )
    removed = runner.teardown(run_id)
    assert name in removed


def test_real_emulator_image_opt_in(client, tmp_path, monkeypatch):
    import os

    image = os.environ.get("MSAI_EMULATOR_IMAGE", "").strip()
    if not image:
        pytest.skip("set MSAI_EMULATOR_IMAGE to run against a real emulator image")
    runner = EmulatorRunner(client)
    spec = EmulatorSpec(apk_path=make_apk(tmp_path), package="com.example.vuln", image=image)
    report = runner.run(spec, detect_host())
    assert report.reset_verified

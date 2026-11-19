"""Host capability detection for the Android emulator (v0.9).

The emulator needs hardware virtualization (KVM on Linux). Docker alone
does not provide it. Detection is explicit so an unsupported host fails
with a clear explanation instead of silently degrading isolation.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

KVM_DEVICE = Path("/dev/kvm")
CPUINFO = Path("/proc/cpuinfo")


class EmulatorUnsupportedError(Exception):
    """The host cannot run the disposable Android emulator safely."""


@dataclass(frozen=True)
class HostCapability:
    kvm_present: bool
    kvm_accessible: bool
    cpu_virtualization: bool
    docker_available: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def emulator_supported(self) -> bool:
        return (
            self.kvm_present
            and self.kvm_accessible
            and self.cpu_virtualization
            and self.docker_available
        )

    def summary(self) -> str:
        if self.emulator_supported:
            return "emulator: supported (KVM available, docker present)"
        return "emulator: UNSUPPORTED — " + "; ".join(self.reasons)


def detect_host(
    kvm_device: Path = KVM_DEVICE,
    cpuinfo: Path = CPUINFO,
    env: dict[str, str] | None = None,
) -> HostCapability:
    env_map = dict(os.environ) if env is None else dict(env)
    reasons: list[str] = []

    kvm_present = kvm_device.exists()
    kvm_accessible = False
    if kvm_present:
        try:
            kvm_accessible = os.access(kvm_device, os.R_OK | os.W_OK)
        except OSError:
            kvm_accessible = False
        if not kvm_accessible:
            reasons.append(f"{kvm_device} is not readable/writable by this user")
    else:
        reasons.append(
            f"{kvm_device} not present (enable virtualization / add user to the kvm group)"
        )

    cpu_virtualization = False
    try:
        text = cpuinfo.read_text(errors="ignore").lower()
        cpu_virtualization = "vmx" in text or "svm" in text
    except OSError:
        cpu_virtualization = False
    if not cpu_virtualization:
        reasons.append("CPU virtualization flags (vmx/svm) not found")

    docker_path = env_map.get("MSAI_DOCKER_PATH", "").strip() or None
    docker_available = shutil.which(docker_path or "docker") is not None
    if not docker_available:
        reasons.append("docker CLI not found on PATH")

    return HostCapability(
        kvm_present=kvm_present,
        kvm_accessible=kvm_accessible,
        cpu_virtualization=cpu_virtualization,
        docker_available=docker_available,
        reasons=tuple(reasons),
    )


def require_emulator_support(capability: HostCapability) -> None:
    """Raise with an actionable explanation when the host cannot run it."""
    if capability.emulator_supported:
        return
    raise EmulatorUnsupportedError(
        "Dynamic APK analysis requires an Android emulator with hardware "
        "virtualization; this host does not support it, so isolation cannot be "
        "guaranteed. Refusing to run rather than degrading isolation.\n"
        "  reasons:\n" + "\n".join(f"    - {r}" for r in capability.reasons) + "\n  options:\n"
        "    - enable virtualization (BIOS/UEFI) and KVM, add your user to the "
        "'kvm' group\n"
        "    - use a dedicated VM/host with virtualization support\n"
        "    - static analysis still works: 'mauberesec apk analyze <apk>'"
    )

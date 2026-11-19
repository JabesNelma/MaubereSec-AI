# Platform Support Matrix (v1.0) — evidence-based

**Rule:** a platform is listed as supported only for the layers actually
exercised on it. Statements below match recorded test evidence in `progres.md`;
nothing is claimed from assumption.

| Platform | CLI + scanners | Local lab (Docker) | APK dynamic (emulator) | Evidence |
|---|---|---|---|---|
| Linux (Fedora 44, Docker 29.9.3, Python 3.14) | **Verified** | **Verified** | **Verified in orchestration** (stub image; real image opt-in) | Full test suite + manual runs in `progres.md` |
| macOS (Docker Desktop) | Not tested | Not tested | Not tested | — (Docker Desktop's VM may restrict nested virtualization) |
| Windows + WSL2 | Not tested | Not tested | Not tested | — |
| WSL2 + Docker Desktop | Not tested | Not tested | Not tested | — |

## Layer detail

| Layer | Requirement | Availability notes |
|---|---|---|
| CLI, policy, reports, MCP | Python >= 3.11 | Cross-platform; no platform-specific code paths beyond XDG fallbacks |
| Container scanners (`audit`) | Docker CLI + daemon | Works wherever Docker runs with bind mounts; SELinux hosts need the `label=disable` behaviour already implemented |
| Local labs (`lab`) | Docker with bridge networks and resource limits | Docker Desktop supports this; not yet exercised |
| APK static (`apk analyze`) | Docker only | Works wherever Docker runs |
| APK dynamic (`apk dynamic`) | `/dev/kvm` + CPU virtualization | Linux with KVM only. Docker Desktop for macOS/Windows generally does not expose `/dev/kvm`; the command refuses with guidance instead of degrading isolation |
| Cloud models | Outbound HTTPS | Any platform |

## How to extend this matrix

Run on the target platform and record in `progres.md`:
```bash
mauberesec doctor
pytest -q                      # unit + security
pytest -q -m integration       # requires Docker (and KVM for emulator tests)
```
Only then update the corresponding cell to **Verified**.

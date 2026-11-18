# Lab templates

Lab templates for v0.3 are defined in code at
`mauberesec/docker/labs.py::builtin_profiles()` so they are validated by
Pydantic and covered by tests. Each template declares:

- a **dedicated internal bridge network** on a private /24 subnet,
- one or more **hardened service containers** (memory/CPU/PID limits,
  `cap_drop ALL` plus an allowlist of extra capabilities, no-new-privileges,
  read-only rootfs with tmpfs, no host ports, no host mounts),
- optional **health checks** used by `mauberesec lab verify`.

## Available templates

| Name | Subnet | Description |
|---|---|---|
| `demo-web` | 10.66.7.0/24 | Static nginx target for passive check development |

## Lifecycle

```bash
mauberesec lab list
mauberesec lab register demo-web    # create + register (grants LOCAL_LAB policy)
mauberesec lab verify demo-web      # network, labels, health, hardening
mauberesec lab reset demo-web       # teardown + fresh create
mauberesec lab teardown demo-web    # remove only this lab's labeled resources
```

Teardown only removes resources carrying the labels
`mauberesec.managed=true` and `mauberesec.lab=<name>`.

Adding a new template = add a `LabProfile` entry in `builtin_profiles()`.
File-based templates may arrive in a later milestone; profile schemas are
already serializable to JSON and persisted in `lab_registrations`.

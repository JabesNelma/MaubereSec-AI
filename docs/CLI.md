# CLI Reference (v1.0)

Exit codes: `0` success · `1` blocked/failed at runtime · `2` invalid input or
configuration · `3` host capability missing (emulator) · `130` cancelled (Ctrl+C).

## Environment (foundation)

| Command | Purpose |
|---|---|
| `mauberesec --help` / `--version` | Usage and version |
| `mauberesec doctor [--json]` | Environment, docker, emulator, cloud config checks |
| `mauberesec config show` | Resolved secret-free configuration |
| `mauberesec models list` / `models test` | Provider model listing / credential+connectivity check |

## Assessment

| Command | Purpose |
|---|---|
| `mauberesec scan <url> [--auth-reference R --authorized-by W]` | Passive website assessment (live requires authorization) |
| `mauberesec audit <path> [--inventory-only]` | Local source-code audit (containerized scanners) |
| `mauberesec apk analyze <apk> [--metadata-only]` | APK static analysis |
| `mauberesec apk dynamic <apk> [--package P] [--dry-run]` | **Experimental** emulator run |
| `mauberesec agent plan <target> [--use-ai]` | Generate a bounded plan without executing |
| `mauberesec agent run <target> [--max-steps N] [--use-ai]` | Plan and execute under budgets |

## Labs

| Command | Purpose |
|---|---|
| `mauberesec lab list` / `register <name>` / `verify <name>` | Manage disposable labs |
| `mauberesec lab test <name> [--confirm-state-change] [--reset-after]` | Controlled red-team validation |
| `mauberesec lab reset <name>` / `teardown <name>` | Restore baseline / remove resources |

## MCP

| Command | Purpose |
|---|---|
| `mauberesec mcp list` | Configured servers + read-only discovery (nothing auto-connects) |
| `mauberesec mcp call <server> <tool> [--args JSON]` | Policy-checked invocation (trusted servers only) |

## Reporting

| Command | Purpose |
|---|---|
| `mauberesec history [--limit N] [--json]` | Recent assessments |
| `mauberesec assessment show <id>` | One assessment with findings |
| `mauberesec report generate <id> [--out DIR] [--print]` | Write Markdown + JSON reports |
| `mauberesec report schema` | Print the report JSON Schema |

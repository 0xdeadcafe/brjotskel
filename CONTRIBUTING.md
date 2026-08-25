# Contributing

How to add playbooks, extend the agent, run tests, and keep the tool sharp.

---

## Ground rules

- **Native OS commands only on target hosts.** No curl downloads, no pip installs, no binary uploads inside playbooks.
- **Read-only by default.** Playbooks that change host state must say so prominently at the top.
- **Evidence first.** Any script that destroys volatile state (killing processes, locking accounts) must capture that state first.
- **Test before pushing.** `bash bin/test` must pass cleanly — syntax checks, unit tests, executable bit policy.
- **Record as you go.** New capabilities belong in the appropriate SKILL.md inventory table and, if relevant, in the README platform coverage table.

---

## Adding playbooks

### Where to put them

```
.pi/skills/gather-playbooks/linux/         # bash, read-only collection
.pi/skills/gather-playbooks/windows/       # PowerShell, read-only collection
.pi/skills/gather-playbooks/macos/         # bash, read-only collection
.pi/skills/gather-playbooks/network-device/ # command references, not automated
.pi/skills/host-ir-playbooks/linux/        # bash, investigation-focused
.pi/skills/host-ir-playbooks/windows/      # PowerShell, investigation-focused
.pi/skills/host-ir-playbooks/macos/        # bash, investigation-focused
.pi/skills/containment-playbooks/linux/    # bash, state-changing
.pi/skills/containment-playbooks/windows/  # PowerShell, state-changing
.pi/skills/containment-playbooks/macos/    # bash, state-changing
.pi/skills/eradication-playbooks/linux/    # bash, state-changing
.pi/skills/eradication-playbooks/windows/  # PowerShell, state-changing
.pi/skills/eradication-playbooks/macos/    # bash, state-changing
```

### Script standards

```sh
#!/bin/sh
# category/platform/name.sh — One-line description
# Requires: root / admin / user context
# State-changing: YES/NO — brief note on what changes if YES
# Pattern: EVIDENCE → ACT → VERIFY  (for state-changing scripts)
#
# Parameters:
#   TARGET_FOO  — description (required/optional)
#
# Usage:
#   TARGET_FOO=bar remote_exec(session="host01", command="<paste>")
```

- Shebang (`#!/...`) is required. `bin/smoke-check` enforces the executable bit on every tracked shebang script.
- Section headers: `sec(){ printf '\n=== %s ===\n' "$1"; }` — consistent with existing scripts.
- For state-changing scripts: always end with an `INTEL UPDATE SNIPPET` section that emits a ready-to-paste `intel_update(...)` call.
- No persistent artifacts on target: no temp files left behind, no writes to target logs.

### After adding a script

1. Add the script to the relevant `SKILL.md` inventory table in its skill directory
2. Add it to `docs/playbooks.md`
3. Update the platform summary table in `README.md` if the count changes
4. Run `bash bin/test` — the smoke check will fail if the shebang is present but `+x` is missing

---

## Adding intel-snippet subcommands

`bin/intel-snippet` is a Python script. To add a subcommand:

1. Add a `cmd_<name>` handler function
2. Add a `sub.add_parser('<name>', parents=[common])` with appropriate arguments
3. Call `add_common_source(data, args)` for provenance
4. Call `print_result(category, id, data, summary)`
5. Add a test in `tests/python/test_intel_snippet.py`

---

## Extension development

Extensions live in `.pi/extensions/`. Pi loads all `.ts` files in that directory automatically. Shared library code lives in `.pi/extensions/lib/`.

```
.pi/extensions/
  remote-session.ts        — tool registration + slash commands
  intel-store.ts           — intel store tools
  persona.ts               — Ghost persona + live intel state injection
  lib/
    remote-types.ts        — shared types, constants, logging
    remote-helpers.ts      — shell quoting, platform detection
    remote-session-core.ts — marker commands, relay builders, tunnel arg builders
    protocol-adapters/
      ssh.ts               — SSH connection adapter
      winrm.ts             — WinRM/pwsh adapter
      tcp-telnet.ts        — TCP + telnet adapters
    tunnel-manager.ts      — SSH tunnel spawn + lifecycle
    relay-manager.ts       — relay setup, verification, teardown
    operator-shortcuts.ts  — phase shortcut formatters + prompts
    intel-helpers.ts       — intel schema validation, status enums
    intel-store-core.ts    — intel CRUD, attack graph, timeline filtering
    intel-permissions.ts   — file permission hardening
    simple-yaml.ts         — in-process YAML parser/dumper
```

**Live-reload during development:** use the `dev` compose service so extension and skill changes are visible without rebuilding:

```sh
docker compose run --rm dev
```

Or without Compose:

```sh
docker run --rm -it \
  -v "$PWD/.pi:/opt/brjotskel/.pi" \
  -v "$PWD/workspace:/opt/brjotskel/workspace" \
  -v "$PWD/logs:/opt/brjotskel/logs" \
  brjotskel:local
```

Rebuild the image only when changing `bin/`, `Dockerfile`, or base OS dependencies.

---

## Running tests

```sh
bash bin/test
```

The test suite:
- Shell, Python, TypeScript, PowerShell syntax checks
- Shebang executable bit policy check
- Banned-pattern checks (stale tool references)
- **Python unit tests** (`tests/python/`): `intel-snippet` output format, `ir-log` audit entries (text + JSONL)
- **Node unit tests** (`tests/node/`): extension registration, intel store CRUD and validation, relay helpers, session management, operator shortcuts, YAML round-trip, attack graph, timeline filtering, tunnel manager lifecycle, relay manager orchestration

Current counts: **16 Python** | **78 Node** — all must pass before pushing.

---

## CI

GitHub Actions runs the full test harness and a Docker smoke build on every push and pull request. See `.github/workflows/ci.yml`.

---

## Current capability status

| Capability | Status |
|-----------|--------|
| AI-native investigation agent (pi) | ✅ |
| Persistent multi-protocol remote sessions — SSH, WinRM, TCP, telnet | ✅ |
| SSH tunnels (local, remote, dynamic SOCKS) | ✅ |
| Native TCP relays (socat, ncat, nc, netsh portproxy) | ✅ |
| Structured intel store with schema validation and lifecycle management | ✅ |
| Phase shortcuts: `/land`, `/assess`, `/pursue`, `/contain`, `/eradicate`, `/verify` | ✅ |
| `/scope`, `/map`, `/brief`, `/incident` agent commands | ✅ |
| Linux gather playbooks — 19 scripts | ✅ |
| Windows gather playbooks — 27 scripts | ✅ |
| macOS gather playbooks — 10 scripts | ✅ |
| Network device CLI references — Cisco IOS/NX-OS, Juniper JunOS | ✅ |
| Host IR playbooks — Linux (2), Windows (8), macOS (2) | ✅ |
| Containment playbooks — Linux/Windows/macOS | ✅ |
| Eradication playbooks — Linux/Windows/macOS | ✅ |
| Privilege escalation assessment — Linux, Windows, macOS | ✅ |
| Kerberoasting + AS-REP roast workflows | ✅ |
| Cloud credential enumeration — EC2/Azure/GCP IMDS | ✅ |
| Binary integrity verification — Linux, Windows | ✅ |
| Operator audit logging — text and JSONL | ✅ |
| `ir-search` — fzf-based interactive log search | ✅ |
| `intel-snippet` — normalized `intel_add(...)` generation | ✅ |
| Persona auto-surfaces live intel state in every agent turn | ✅ |

For the open backlog, see [TODO.md](TODO.md).

# Contributing & Roadmap

## Current capabilities

| Capability | Status |
|-----------|--------|
| AI-native investigation agent (pi) | ✅ |
| Persistent multi-protocol remote sessions — SSH, WinRM, TCP, telnet | ✅ |
| SSH tunnels (local, remote, dynamic SOCKS) with key/password/ProxyJump auth | ✅ |
| Native TCP relays through pivot hosts (socat, ncat, nc, netsh portproxy) | ✅ |
| Structured intel store with schema validation and lifecycle management | ✅ |
| Phase shortcuts: `/land`, `/assess`, `/pursue`, `/contain`, `/eradicate`, `/verify` | ✅ |
| Linux gather playbooks — 16 scripts | ✅ |
| Windows gather playbooks — 24 scripts including full AD enumeration | ✅ |
| macOS gather playbooks — 9 scripts | ✅ |
| Linux host-IR playbooks | ✅ |
| Windows host-IR playbooks — event logs, Sysmon, PowerShell reconstruction | ✅ |
| macOS host-IR playbooks | ✅ |
| Privilege escalation assessment — Linux, Windows, macOS | ✅ |
| Shell command references — 15 native-OS reference docs | ✅ |
| Network discovery playbooks (nmap, NSE) | ✅ |
| Harness toolchain — Impacket, NetExec, proxychains | ✅ |
| Operator audit logging | ✅ |
| `intel-snippet` helper for normalized intel_add generation | ✅ |

---

## Known gaps

### 🔴 No containment playbooks

The runbook has containment commands as reference text. What's missing is a structured **skill** with ready-to-run scripts that follow the evidence-first pattern: verify the target → preserve state → execute containment → verify success → produce `intel_update` output.

Proposed: `.pi/skills/containment-playbooks/` with platform-specific scripts for process kill, C2 block, account disable, and network isolation. Each script should be safe to run without knowing ahead of time whether it'll succeed — verify first, act second.

---

### 🔴 No eradication playbooks

Persistence removal commands exist in the runbook as reference. What's missing is a structured eradication skill where each script pairs removal with evidence capture and post-removal verification.

Proposed: `.pi/skills/eradication-playbooks/` covering cron, systemd, registry, scheduled tasks, WMI subscriptions, SSH keys, launch daemons, and shell profile hooks — all with verification steps.

---

### 🟠 No credential validation automation

The core pursuit loop (recover credential → validate against other hosts → pivot) is entirely manual. The analyst must remember to test each credential against each discovered host.

Proposed: A skill or extension tool that takes a credential ID and a target list and attempts validation using `netexec`, `ssh`, etc., then writes `valid_on` results back into the intel store automatically.

---

### 🟠 No multi-host correlation view

`intel_summary` reports counts. It doesn't show the attack graph — which hosts share credentials, what the blast radius looks like, or which pivot paths are still active.

Proposed: An `intel_map` command that renders a text-based attack graph: host nodes, credential edges, active sessions, and pivot chains in one view.

---

### 🟠 No evidence collection scripts

When a host has no central logging, volatile evidence needs to be bagged before containment changes it. No structured evidence collection workflow exists today.

Proposed: Platform-specific scripts that archive key artifacts (auth logs, shell histories, cron configs, recent modified files, network state snapshot) and a workflow for pulling the archive back to `workspace/evidence/<host>/`.

---

### 🟡 No binary integrity verification

On hosts without EDR, `ps`, `ss`, and `netstat` may have been replaced by the attacker. No workflow exists for verifying binary integrity using native package manager signatures.

Proposed: `gather-playbooks/linux/integrity-check.sh` using `rpm -Va` / `dpkg --verify`, LD_PRELOAD checks, and `/proc/*/maps` inspection. Windows equivalent using `Get-AuthenticodeSignature`.

---

### 🟡 No network reachability probe

`enum-network.sh` shows current connections. It doesn't map what the host can *reach* — which matters for pivot planning after landing.

Proposed: A lightweight reachability probe that tests common service ports (22, 445, 3389, 5985) against hosts discovered via ARP, routes, `/etc/hosts`, and DNS, using only native tools.

---

## Adding playbooks

Drop scripts into the appropriate skill directory:

```
.pi/skills/gather-playbooks/linux/      # bash scripts
.pi/skills/gather-playbooks/windows/    # PowerShell scripts
.pi/skills/gather-playbooks/macos/      # bash scripts
.pi/skills/host-ir-playbooks/linux/     # bash scripts
.pi/skills/host-ir-playbooks/windows/   # PowerShell scripts
.pi/skills/host-ir-playbooks/macos/     # bash scripts
```

Script guidelines:
- **Native OS commands only** — no curl downloads, no binary staging, no pip installs from within the script
- **Read-only by default** — scripts that write state must say so clearly in a comment block at the top
- **Structured text output** — each section gets a clear header so findings are parseable by the agent
- **No persistent artifacts on target** — no temp files left behind, no writes to target logs

Add the new script to the relevant `SKILL.md` inventory table.

---

## Adding intel-snippet subcommands

`bin/intel-snippet` is a Python script. To add a subcommand:

1. Add a `add_subparsers` entry in `bin/intel-snippet`
2. Write a handler that calls `emit(yaml_data, intel_add_call_string)`
3. Add a test in `tests/python/test_intel_snippet.py`

---

## Running tests

```sh
bash bin/test
```

The test suite covers:
- Shell, Python, and PowerShell syntax smoke check
- Python unit tests: `intel-snippet` output format, `ir-log` audit entries
- Node unit tests: extension registration, intel store CRUD and validation, relay helpers, session management, operator shortcuts, YAML round-trip

All tests must pass before pushing. CI runs the same suite plus a Docker smoke build.

---

## Extension development

Extensions live in `.pi/extensions/`. Pi loads all `.ts` files in that directory automatically. Shared library code lives in `.pi/extensions/lib/`.

Mount `.pi/` when running locally to make changes visible without rebuilding:

```sh
docker run --rm -it \
  -v "$PWD/.pi:/opt/brjotskel/.pi" \
  -v "$PWD/workspace:/opt/brjotskel/workspace" \
  -v "$PWD/logs:/opt/brjotskel/logs" \
  brjotskel:local
```

See [architecture.md](architecture.md) for the extension API and intel store schema.

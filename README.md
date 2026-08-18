# brjotskel

[![CI](https://github.com/0xdeadcafe/brjotskel/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/0xdeadcafe/brjotskel/actions/workflows/ci.yml)

An authorized incident response and threat-pursuit container built around **pi**.

Built for defenders operating in environments without EDR: investigate active compromises, recover exposed credentials, pivot through attacker-controlled infrastructure, take back control using only native tooling on target hosts, and track everything as structured intel.

## What this repo provides

### Containerized operator tooling

- `pi` — globally installed and launched by default when the container starts
- `ssh`, `sshpass` — interactive access, password-based SSH, ProxyJump, port forwards
- `pwsh` — PowerShell and WinRM workflows
- `nmap`, `ncat`, `nc` — service discovery and relay
- `proxychains4` — SOCKS-based pivoting
- Impacket — `psexec.py`, `wmiexec.py`, `smbexec.py`, `secretsdump.py`, `ntlmrelayx.py`
- NetExec (`netexec`; Docker aliases `nxc` to `netexec` if upstream only installs `nxc`) — credential validation and lateral-movement mapping
- `curl`, `jq`, `git`, `python3`, `ripgrep`, `fd`, `neovim` — general support tools
- `ir-log` — local operator audit logger
- `intel-snippet` — helper for generating normalized `intel_add(...)` payloads

### Bundled pi extensions

- `.pi/extensions/remote-session.ts`
  - Persistent named SSH, WinRM, TCP, and telnet sessions
  - Multiple concurrent sessions with preserved shell state
  - SSH local/remote port forwards and dynamic SOCKS proxies
  - **TCP relays through pivot hosts** using native tools (socat, ncat, nc, netsh portproxy)
  - Session, tunnel, and relay audit logging
  - Senior-responder phase shortcuts: `/land`, `/assess`, `/pursue`, `/contain`, `/eradicate`, `/verify`
- `.pi/extensions/intel-store.ts`
  - YAML-backed intel store for hosts, credentials, accounts, and pivot paths
  - Query helpers for access mapping
  - Schema validation plus `intel_update` lifecycle/status changes
  - Timeline tracking for discoveries and response actions

### Bundled pi package

- `pi-smart-fetch` — browser-like TLS/HTTP fingerprints for `web_fetch` and `batch_web_fetch`

### Bundled pi skills

| Skill | Purpose |
|-------|---------|
| `gather-playbooks/` | Post-exploitation triage: credentials, network, persistence, security tools. Includes **first-look** (30-sec situational awareness) |
| `host-ir-playbooks/` | Host-centric IR: prove/disprove compromise, hunt persistence, reconstruct attacker activity |
| `escalate-playbook/` | Privilege-escalation assessment: sudo, SUID, services, LOLBAS/GTFOBins |
| `shell-commands/` | Native command reference: forensics, persistence, credentials, lateral movement, containment, eradication |
| `nmap-playbooks/` | Network discovery: Nmap, NSE, Ncat, Nping, Ndiff |

## Core workflow

```
LAND → ASSESS → PURSUE → CONTAIN → ERADICATE → VERIFY
```

| Phase | Capability |
|-------|-----------|
| **Land** | SSH/WinRM/TCP sessions, ProxyJump, key-based or password auth |
| **Assess** | 30-sec first-look, full triage, persistence hunting, event log analysis |
| **Pursue** | Credential recovery → validation → pivot. SSH tunnels, SOCKS proxies, native relays |
| **Contain** | Kill processes, block C2, disable accounts, isolate hosts |
| **Eradicate** | Remove persistence, force credential rotation, verify clean |
| **Verify** | Re-run first-look, validate no reconnection, confirm eradication |

See [docs/analyst-runbook.md](docs/analyst-runbook.md) for operational details.

### Operator phase shortcuts

For senior responders moving fast, phase commands are **command accelerators**, not case/report workflow gates:

| Command | Purpose |
|---------|---------|
| `/land` | Show fast access, pivot, and immediate post-landing primitives |
| `/assess <session>` | Show platform-specific first-look and follow-up triage playbooks |
| `/pursue` | Show intel/credential/pivot chase-board commands |
| `/contain <session>` | Show evidence-first containment command pack; no auto-execution |
| `/eradicate <session>` | Show evidence-backed persistence removal workflow; no auto-execution |
| `/verify <session>` | Show post-action verification checks |

Add `--prompt` to stage an editable agent prompt instead of only displaying the shortcut, e.g. `/assess web01 --prompt`.

## Pivoting capabilities

| Method | When to use |
|--------|-------------|
| SSH ProxyJump | Direct multi-hop SSH chain |
| SSH local forward | Access a specific service through an SSH-capable pivot |
| SSH dynamic SOCKS | Route multiple tools through an SSH pivot |
| `remote_relay` (socat/ncat) | Pivot through a Linux host without SSH tunneling |
| `remote_relay` (netsh portproxy) | Pivot through a Windows host without OpenSSH |
| `remote_relay` (nc fifo) | Last-resort relay using native netcat variants |

See [docs/relay-pivoting.md](docs/relay-pivoting.md) for the decision tree and chaining examples.

## Safety model

See [CONSTITUTION.md](CONSTITUTION.md).

- Stay within the authorized incident scope
- Prefer evidence collection before destructive action
- Log operator activity locally with enough context to reconstruct what happened
- Prefer native tooling on target hosts — no binary uploads

## Repository layout

```text
.pi/extensions/         pi extensions: remote sessions, tunnels, relays, intel store
.pi/skills/             bundled IR, escalation, shell, and nmap playbooks
.pi/npm/                local pi package state
bin/                    helper utilities: ir-log, intel-snippet, smoke-check
docs/                   architecture, runbook, and workflow docs
logs/                   local audit and remote-session logs
workspace/              optional operator scratch space mounted from host
Dockerfile              container image definition
CONSTITUTION.md         safety model and rules of engagement
```

## Quick start

### Build and run

```sh
docker build -t brjotskel:local .

docker run --rm -it \
  -v "$PWD/logs:/opt/brjotskel/logs" \
  -v "$PWD/.pi:/opt/brjotskel/.pi" \
  -v "$PWD/workspace:/opt/brjotskel/workspace" \
  brjotskel:local
```

### Shell instead of pi

```sh
docker run --rm -it --entrypoint bash \
  -v "$PWD/logs:/opt/brjotskel/logs" \
  -v "$PWD/.pi:/opt/brjotskel/.pi" \
  -v "$PWD/workspace:/opt/brjotskel/workspace" \
  brjotskel:local
```

### Validate changes

```sh
bash bin/test
```

## Example usage

### First-look (30-second triage)

```text
remote_connect(protocol="ssh", target="root@10.10.10.5", name="web01", password="...")
remote_exec(session="web01", command="<paste linux/first-look.sh>")
```

### Pivot when target is unreachable from harness

```text
# SSH tunnel (pivot has SSH; supports identity=, password=, and proxy_jump=):
remote_tunnel(type="local", via="root@web01", local_port=2222, remote_host="internal", remote_port=22)
remote_tunnel(type="dynamic", via="root@web01", local_port=1080, password="...")
remote_connect(protocol="ssh", target="admin@localhost", port=2222, name="internal01")

# Native relay (pivot has no SSH — Windows with WinRM only):
remote_relay(session="dc01", target_host="10.10.30.10", target_port=445, listen_port=44450)

# SOCKS for multi-tool routing through a jump chain:
remote_tunnel(type="dynamic", via="root@web01", local_port=1080, proxy_jump="user@jumpbox")
# proxychains netexec smb 10.10.20.0/24 -u admin -H <hash>
```

### Credential trail

```text
# Recover
remote_exec(session="web01", command="cat /etc/shadow")

# Record
intel_add(category="credential", id="root-hash", data="type: password\nusername: root\nsecret: ...\nstatus: active\nvalid_on:\n  - web01\nsource:\n  host: web01\n  method: shadow file")

# Validate from harness
# netexec ssh 10.10.10.0/24 -u root -p '<pass>'

# Pivot
remote_connect(protocol="ssh", target="root@10.10.20.5", name="db01", password="...")
```

### Track and query intel

```text
intel_add(category="host", id="web01", data="ip: 10.10.10.5\nplatform: linux\nstatus: compromised\nsource:\n  method: authorized scope / live triage")
intel_update(category="host", id="web01", fields="status: contained\nnotes: C2 blocked and suspicious process killed", summary="web01 contained")
intel_query(query_type="for_host", target="web01")
intel_summary()
intel_timeline(action="view")
```

## Platform support

| Platform | Access | Triage | Pivoting |
|----------|--------|--------|----------|
| Linux | SSH | Full (first-look + 15 gather scripts + IR + escalation) | SSH tunnels, socat/ncat/nc relays |
| Windows | WinRM, SSH | Full (first-look + 24 gather scripts + 7 IR scripts + escalation) | netsh portproxy, ncat relays |
| macOS | SSH | Good (first-look + 8 gather scripts + live-response + escalation) | SSH tunnels, socat/ncat relays |
| Network devices | SSH, telnet | Limited (CLI access, operator-driven) | Not applicable |

TCP/telnet targets accept `host:port`, `[IPv6]:port`, or a separate `port=` value; no-banner services are treated as best-effort connected when the socket stays open.

## CI

GitHub Actions runs the test harness and a Docker image smoke build on every push:
- `.github/workflows/ci.yml` → `bash bin/test`
- `.github/workflows/ci.yml` → `docker build -t brjotskel:ci .`

## Documentation

- [docs/analyst-runbook.md](docs/analyst-runbook.md) — Operational workflow reference
- [docs/relay-pivoting.md](docs/relay-pivoting.md) — Pivoting when SSH isn't available
- [docs/architecture.md](docs/architecture.md) — Component design and future direction
- [docs/intel-import-workflow.md](docs/intel-import-workflow.md) — Normalizing findings into intel
- [CONSTITUTION.md](CONSTITUTION.md) — Safety model and rules of engagement

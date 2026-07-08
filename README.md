# brjotskel

An authorized incident response and threat-pursuit container built around **pi**.

It is intended for defenders who need to investigate an active compromise from inside an approved scope: recover exposed credentials, maintain remote access to compromised systems, pivot through attacker-controlled infrastructure, track discoveries as structured intel, and support containment and eradication.

## What this repo provides

### Containerized operator tooling

- `ssh` — interactive access, ProxyJump, port forwards
- `pwsh` — PowerShell and WinRM workflows
- `nmap`, `ncat`, `nc` — service discovery and relay
- `proxychains4` — SOCKS-based pivoting
- Impacket — `psexec.py`, `wmiexec.py`, `smbexec.py`, `secretsdump.py`, `ntlmrelayx.py`
- NetExec — credential validation and lateral-movement mapping
- `curl`, `jq`, `git`, `python3`, `neovim` — general support tools
- `ir-log` — local operator audit logger

### pi extensions

- `.pi/extensions/remote-session.ts`
  - Persistent named SSH, WinRM, TCP, and telnet sessions
  - Multiple concurrent sessions with preserved shell state
  - SSH local/remote port forwards and dynamic SOCKS proxies
  - Session and tunnel audit logging
- `.pi/extensions/intel-store.ts`
  - YAML-backed intel store for hosts, credentials, accounts, and pivot paths
  - Query helpers for access mapping
  - Timeline tracking for discoveries and response actions

### pi skills

- `.pi/skills/gather-playbooks/` — triage playbooks for compromised Linux, Windows, and macOS hosts
- `.pi/skills/host-ir-playbooks/` — host-centric IR workflows for confirming compromise and understanding attacker activity
- `.pi/skills/shell-commands/` — native command reference for investigation, containment, persistence checks, and credential recovery

## Core workflows

| Capability | Purpose |
|---|---|
| Credential recovery | Identify access the attacker exposed, cached, or reused |
| Remote host triage | Collect system, network, persistence, and security-tool state |
| Host compromise assessment | Prove or disprove compromise on a specific system |
| Pivoting | Reach additional attacker-touched systems through compromised hosts |
| Lateral movement mapping | Validate recovered credentials and determine blast radius |
| Intel tracking | Record hosts, accounts, credentials, pivots, and timeline events |
| Containment and eradication | Remove persistence, disable access, and verify clean state |

## Safety model

See [CONSTITUTION.md](CONSTITUTION.md).

Key rules:

- Require an authorization context via `BRJOTSKEL_AUTH_CONTEXT`
- Stay within the authorized incident scope
- Prefer evidence collection before destructive action
- Log operator activity locally
- Prefer native tooling on target hosts

## Repository layout

```text
.pi/extensions/         pi extensions: remote sessions, tunnels, intel store
.pi/skills/             gather, host-IR, and shell-command skills
bin/                    ir-log and intel-snippet helper utilities
docs/                   architecture and design docs
logs/                   local audit and remote-session logs
workspace/              operator working directory
Dockerfile              container image definition
CONSTITUTION.md         safety model and rules of engagement
README.md               project overview
```

## Quick start

Build the image:

```sh
docker build -t brjotskel:local .
```

Run it:

```sh
docker run --rm -it \
  -v "$PWD/logs:/opt/brjotskel/logs" \
  -v "$PWD/workspace:/workspace" \
  brjotskel:local
```

Set the required authorization context before operating:

```sh
export BRJOTSKEL_AUTH_CONTEXT="INC-2026-0042 active compromise - authorized threat pursuit"
```

## Example usage

### Audit a manual action

```sh
ir-log "nmap scan 10.10.10.0/24 -p 22,445,3389"
nmap -sT -Pn 10.10.10.0/24 -p 22,445,3389 --open
```

### Use pi remote sessions

```text
remote_connect(protocol="ssh", target="root@10.10.10.5", name="web01")
remote_exec(session="web01", command="hostname; id; ss -tunap")
remote_tunnel(type="dynamic", via="root@10.10.10.5", local_port=1080, description="SOCKS via web01")
remote_sessions()
```

Notes:
- SSH and WinRM sessions preserve shell state between `remote_exec` calls.
- TCP and telnet sessions are best-effort for line-oriented or legacy services.
- The `/remote-connect` slash command is preview-oriented; use the `remote_connect(...)` tool for actual connections.

### Track discoveries as intel

```text
intel_add(category="host", id="web01", data="ip: 10.10.10.5
platform: linux
status: compromised
source:
  discovered_from: initial triage
", summary="Confirmed compromised Linux web host")

intel_query(query_type="for_host", target="web01")
intel_summary()
```

## Data and runtime paths

- Track discovered scope in `workspace/`, such as `workspace/scope.yaml` and `workspace/pivot-chain.md`.
- The intel store defaults to `./intel/` under the working directory, or `BRJOTSKEL_INTEL_DIR` if set.
- Remote session logs default to `$BRJOTSKEL_LOG_DIR/remote-sessions/`; otherwise they are written under `./logs/remote-sessions/` in the working directory.
- `ir-log` writes daily audit files to `$BRJOTSKEL_LOG_DIR` when set.

## Platform support snapshot

| Platform | Support level | Notes |
|---|---|---|
| Linux | Strong | SSH/native shell workflows plus triage playbook coverage |
| Windows | Strong | WinRM/PowerShell workflows plus Windows-specific triage coverage |
| macOS | Moderate | SSH/native shell workflows plus macOS gather playbooks |
| Network devices | Limited | SSH CLI access patterns only; operator-driven investigation |

## Additional documentation

- [docs/architecture.md](docs/architecture.md)
- [docs/intel-import-workflow.md](docs/intel-import-workflow.md)
- [CONSTITUTION.md](CONSTITUTION.md)

# brjotskel

[![CI](https://github.com/0xdeadcafe/brjotskel/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/0xdeadcafe/brjotskel/actions/workflows/ci.yml)

An authorized incident response and threat-pursuit container built around **pi**.

It is intended for defenders who need to investigate an active compromise from inside an approved scope: recover exposed credentials, maintain remote access to compromised systems, pivot through attacker-controlled infrastructure, track discoveries as structured intel, and support containment and eradication.

## What this repo provides

### Containerized operator tooling

- `pi` — globally installed and launched by default when the container starts
- `ssh`, `sshpass` — interactive access, password-based SSH, ProxyJump, port forwards
- `pwsh` — PowerShell and WinRM workflows
- `nmap`, `ncat`, `nc` — service discovery and relay
- `proxychains4` — SOCKS-based pivoting
- Impacket — `psexec.py`, `wmiexec.py`, `smbexec.py`, `secretsdump.py`, `ntlmrelayx.py`
- NetExec — credential validation and lateral-movement mapping
- `curl`, `jq`, `git`, `python3`, `ripgrep`, `fd`, `neovim` — general support tools
- `ir-log` — local operator audit logger
- `intel-snippet` — helper for generating normalized `intel_add(...)` payloads
- `pi-smart-fetch` — smarter `web_fetch` with browser-like TLS fingerprints and readable extraction

### Bundled pi extensions

- `.pi/extensions/remote-session.ts`
  - Persistent named SSH, WinRM, TCP, and telnet sessions
  - Multiple concurrent sessions with preserved shell state
  - SSH local/remote port forwards and dynamic SOCKS proxies
  - Session and tunnel audit logging
- `.pi/extensions/intel-store.ts`
  - YAML-backed intel store for hosts, credentials, accounts, and pivot paths
  - Query helpers for access mapping
  - Timeline tracking for discoveries and response actions

### Bundled pi package

- `pi-smart-fetch`
  - Adds `web_fetch` and `batch_web_fetch`
  - Uses browser-like TLS/HTTP fingerprints for better success on defended sites
  - Supports readable extraction for markdown/text output

### Bundled pi skills

- `.pi/skills/gather-playbooks/` — triage playbooks for compromised Linux, Windows, and macOS hosts
- `.pi/skills/host-ir-playbooks/` — host-centric IR workflows for confirming compromise and understanding attacker activity
- `.pi/skills/escalate-playbook/` — privilege-escalation assessment playbooks
- `.pi/skills/shell-commands/` — native command reference for investigation, containment, persistence checks, and credential recovery
- `.pi/skills/nmap-playbooks/` — Nmap, NSE, Ncat, Nping, and Ndiff playbooks for scoped discovery and validation

## Core workflows

| Capability | Purpose |
|---|---|
| Credential recovery | Identify access the attacker exposed, cached, or reused |
| Remote host triage | Collect system, network, persistence, and security-tool state |
| Host compromise assessment | Prove or disprove compromise on a specific system |
| Privilege escalation analysis | Understand how the attacker gained higher privileges |
| Pivoting | Reach additional attacker-touched systems through compromised hosts |
| Lateral movement mapping | Validate recovered credentials and determine blast radius |
| Intel tracking | Record hosts, accounts, credentials, pivots, and timeline events |
| Containment and eradication | Remove persistence, disable access, and verify clean state |

## Safety model

See [CONSTITUTION.md](CONSTITUTION.md).

Key rules:

- Stay within the authorized incident scope
- Prefer evidence collection before destructive action
- Log operator activity locally with enough context to reconstruct what happened
- Prefer native tooling on target hosts

## Repository layout

```text
.pi/extensions/         pi extensions: remote sessions, tunnels, intel store
.pi/skills/             bundled IR, escalation, shell, and nmap playbooks
.pi/npm/                local pi package state
bin/                    helper utilities: ir-log, intel-snippet, smoke-check
docs/                   architecture and workflow docs
logs/                   local audit and remote-session logs
workspace/              optional operator scratch space mounted from host
Dockerfile              container image definition
CONSTITUTION.md         safety model and rules of engagement
README.md               project overview
```

## Quick start

### Validate local changes

```sh
bash bin/smoke-check
bash bin/test
```

### Build the image

```sh
docker build -t brjotskel:local .
```

### Run the container

This image starts `pi` by default and uses `/opt/brjotskel` as the working directory.

```sh
docker run --rm -it \
  -v "$PWD/logs:/opt/brjotskel/logs" \
  -v "$PWD/.pi:/opt/brjotskel/.pi" \
  -v "$PWD/workspace:/opt/brjotskel/workspace" \
  brjotskel:local
```

### Run a shell instead of auto-starting pi

```sh
docker run --rm -it \
  --entrypoint bash \
  -v "$PWD/logs:/opt/brjotskel/logs" \
  -v "$PWD/.pi:/opt/brjotskel/.pi" \
  -v "$PWD/workspace:/opt/brjotskel/workspace" \
  brjotskel:local
```

### Live-edit extensions, skills, or editor config

Mounting `.pi/` is usually enough for day-to-day extension and skill tuning. If you are also iterating on Neovim config:

```sh
docker run --rm -it \
  --entrypoint bash \
  -v "$PWD/logs:/opt/brjotskel/logs" \
  -v "$PWD/.pi:/opt/brjotskel/.pi" \
  -v "$PWD/workspace:/opt/brjotskel/workspace" \
  -v "$PWD/.config/nvim:/etc/xdg/nvim" \
  brjotskel:local
```

## Example usage

### Audit a manual action

```sh
ir-log "nmap scan 10.10.10.0/24 -p 22,445,3389"
nmap -sT -Pn 10.10.10.0/24 -p 22,445,3389 --open
```

### Use pi remote sessions

```text
remote_connect(protocol="ssh", target="root@10.10.10.5", name="web01", password="<password>")
remote_exec(session="web01", command="hostname; id; ss -tunap")
remote_tunnel(type="dynamic", via="root@10.10.10.5", local_port=1080, description="SOCKS via web01")
remote_sessions()

# If a Unix SSH target is misdetected, force shell framing explicitly:
remote_connect(protocol="ssh", target="x0r@172.17.0.1", name="gibson", password="<password>", platform_hint="linux", shell_hint="posix")
```

Notes:
- SSH and WinRM sessions preserve shell state between `remote_exec` calls.
- For password-based SSH, pass `password=` to `remote_connect(...)` instead of shelling out to `sshpass` manually.
- If an SSH target is Unix-like but output shows PowerShell markers such as `Write-Host`, reconnect with `platform_hint="linux"` (or `macos`) and `shell_hint="posix"`.
- `shell_hint` accepts `posix`, `powershell`, or `cmd` when you already know the remote shell type.
- TCP and telnet sessions are best-effort for line-oriented or legacy services.

### Track discoveries as intel

```text
intel_add(category="host", id="web01", data="""ip: 10.10.10.5
platform: linux
status: compromised
source:
  discovered_from: initial triage
""", summary="Confirmed compromised Linux web host")

intel_query(query_type="for_host", target="web01")
intel_summary()
```

### Generate normalized intel snippets

```sh
bin/intel-snippet putty-host \
  --id adminws \
  --host 10.10.30.20 \
  --username admin \
  --session-name adminws \
  --source-host workstation01
```

See [docs/intel-import-workflow.md](docs/intel-import-workflow.md) for more patterns.

## Data and runtime paths

- Container working directory: `/opt/brjotskel`
- Repo-mounted operator scratch space: `/opt/brjotskel/workspace`
- The intel store defaults to `./intel/` under the current working directory, or `BRJOTSKEL_INTEL_DIR` if set.
- Remote session logs default to `$BRJOTSKEL_LOG_DIR/remote-sessions/`; otherwise they are written under `./logs/remote-sessions/` in the working directory.
- `ir-log` writes daily audit files to `$BRJOTSKEL_LOG_DIR` when set and records the local host, operator, event, and optional `BRJOTSKEL_AUTH_CONTEXT`.
- During active development, mount host `.pi/` to `/opt/brjotskel/.pi` so extension and skill edits persist without an image rebuild.

## Platform support snapshot

| Platform | Support level | Notes |
|---|---|---|
| Linux | Strong | SSH/native shell workflows plus triage and escalation playbook coverage |
| Windows | Strong | WinRM/PowerShell workflows plus Windows-specific triage coverage |
| macOS | Moderate | SSH/native shell workflows plus macOS gather playbooks |
| Network devices | Limited | SSH CLI access patterns only; operator-driven investigation |

## CI

GitHub Actions runs the local test harness on every push and pull request:

- `.github/workflows/ci.yml`
- executes `bash bin/test`

## Additional documentation

- [docs/architecture.md](docs/architecture.md)
- [docs/intel-import-workflow.md](docs/intel-import-workflow.md)
- [CONSTITUTION.md](CONSTITUTION.md)

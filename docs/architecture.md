# Architecture

## Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│  Docker Container                                                     │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  pi — AI agent                                               │   │
│  │                                                              │   │
│  │  ┌─────────────────────┐   ┌──────────────────────────┐    │   │
│  │  │  remote-session.ts  │   │    intel-store.ts         │    │   │
│  │  │  ─────────────────  │   │    ─────────────────────  │    │   │
│  │  │  remote_connect     │   │    intel_add              │    │   │
│  │  │  remote_exec        │   │    intel_update           │    │   │
│  │  │  remote_upload      │   │    intel_query            │    │   │
│  │  │  remote_sessions    │   │    intel_get_cred         │    │   │
│  │  │  remote_disconnect  │   │    intel_timeline         │    │   │
│  │  │  remote_tunnel[_cl] │   │    intel_summary          │    │   │
│  │  │  remote_relay[_cl]  │   └────────────┬─────────────┘    │   │
│  │  │                     │                │                   │   │
│  │  │  /land   /assess    │                ▼                   │   │
│  │  │  /pursue /contain   │   workspace/intel/                 │   │
│  │  │  /eradicate /verify │   ├── hosts.yaml                   │   │
│  │  └──────────┬──────────┘   ├── credentials.yaml             │   │
│  │             │              ├── accounts.yaml                │   │
│  │  ┌──────────▼──────────┐   ├── pivots.yaml                  │   │
│  │  │  Skills             │   └── timeline.yaml                │   │
│  │  │  ─────────────────  │                                    │   │
│  │  │  gather-playbooks   │   logs/                            │   │
│  │  │  host-ir-playbooks  │   ├── audit-YYYYMMDD.log           │   │
│  │  │  escalate-playbook  │   └── remote-sessions/             │   │
│  │  │  shell-commands     │                                    │   │
│  │  │  nmap-playbooks     │                                    │   │
│  │  └─────────────────────┘                                    │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Harness tools  (run here — never installed on targets)              │
│  ssh · sshpass · pwsh · nmap · ncat · nc · proxychains4             │
│  secretsdump.py · psexec.py · wmiexec.py · smbexec.py              │
│  ntlmrelayx.py · netexec · ir-log · intel-snippet                  │
└──────────────────────────────────────────────────────────────────────┘
              │ SSH / WinRM / TCP / telnet
   ┌──────────┼──────────────┐
   ▼          ▼              ▼
Linux     Windows        macOS / network device
(native)  (native)       (native)
```

## Container layer

A Debian bookworm-slim image. No daemons. `pi` launches by default; `--entrypoint bash` gives a plain shell.

| Tool | Purpose |
|------|---------|
| `ssh`, `sshpass` | SSH access, ProxyJump chains, port forwards, password-based auth |
| `pwsh` | PowerShell 7, WinRM |
| `nmap`, `ncat`, `nc` | Service discovery, relay setup |
| `proxychains4` | Route any tool through a SOCKS proxy |
| `secretsdump.py` | Remote SAM/LSASS/NTDS credential dump over SMB |
| `psexec.py`, `wmiexec.py`, `smbexec.py` | Lateral movement with recovered credentials |
| `ntlmrelayx.py` | NTLM relay |
| `netexec` | Credential validation at scale — SMB, WinRM, SSH, MSSQL |
| `ir-log` | Appends timestamped audit entries to `logs/audit-YYYYMMDD.log` |
| `intel-snippet` | Generates normalized `intel_add(...)` payloads from gather output |
| `netexec-to-intel` | Converts NetExec success output into `intel_update(valid_on=...)` snippets |
| `check-playbook-inventory` | CI guard for README/docs playbook count drift |
| `clean-local` | Dry-run cleanup for ignored scratch/cache state |
| `curl`, `jq`, `git`, `python3`, `ripgrep`, `fd`, `neovim` | Support tools |

## Agent layer

`pi` is the AI agent. TypeScript extensions add IR-specific tools and persona context, loaded automatically from `.pi/extensions/`.

### remote-session.ts — 9 tools; operator-runtime.ts — slash commands

**Remote access tools:**

| Tool | What it does |
|------|-------------|
| `remote_connect` | Open a named persistent session: SSH, WinRM, TCP, or telnet. Multiple concurrent sessions supported. |
| `remote_exec` | Run a command in a named session. Shell state (cwd, env) persists between calls. |
| `remote_upload` | Write text content to a remote path via heredoc — no scp needed. |
| `remote_sessions` | List all active sessions, tunnels, and relays. |
| `remote_disconnect` | Close a session by name or all sessions. |
| `remote_tunnel` / `remote_tunnel_close` | SSH local, remote, or dynamic SOCKS tunnels. Supports `identity=`, `password=`, `proxy_jump=`. |
| `remote_relay` / `remote_relay_close` | TCP relay on an existing session using socat, ncat, nc, or netsh portproxy. |

**Phase commands** (registered by `operator-runtime.ts` as pi slash commands):

| Command | Produces |
|---------|---------|
| `/land` | Fast-access primitives and post-landing checklist |
| `/assess [session]` | Platform-specific first-look and triage commands for that session |
| `/pursue` | Credential and pivot chase-board |
| `/contain [session]` | Evidence-first containment command pack (no auto-execution) |
| `/eradicate [session]` | Persistence removal workflow (no auto-execution) |
| `/verify [session]` | Post-action verification checks |

Append `--prompt` to stage an editable agent prompt instead of displaying inline.

Every `remote_exec` call is logged to `${BRJOTSKEL_LOG_DIR:-logs}/remote-sessions/` with session name, timestamp, command, and truncated output.

### intel-store.ts — 6 tools

| Tool | What it does |
|------|-------------|
| `intel_add` | Add a new entry with schema validation and provenance tracking. Auto-appends a timeline entry. |
| `intel_update` | Merge updates into an existing entry. Validates lifecycle transitions. Blocks reactivating terminal-status credentials without `force=true`. |
| `intel_query` | Query by host, credential, category, or keyword. |
| `intel_get_cred` | Retrieve a credential secret (password, hash, key path). Refuses terminal-status credentials. |
| `intel_timeline` | Add a manual timeline entry or view recent entries. |
| `intel_summary` | Counts and status breakdown across all categories. |

The intel store normalizes arrays (union-merge by default) and validates schema on every write. Validation errors name the missing field and list allowed enum values.

## Data layer

### Intel store — workspace/intel/

Five YAML files written by the intel-store extension. Readable by querying tools and directly as text.

```
workspace/intel/
├── hosts.yaml           # Compromised/suspected/cleared hosts
├── credentials.yaml     # Harvested passwords, hashes, keys, tokens
├── accounts.yaml        # Domain and local accounts encountered
├── pivots.yaml          # Access paths through the network
└── timeline.yaml        # Chronological investigation record
```

Files are created with restrictive permissions (0600, directory 0700) to protect credential material at rest. The `intel_get_cred` tool refuses to return secrets for credentials with terminal statuses: `rotated`, `expired`, `revoked`, `disabled`, `inactive`, `invalid`.

See [intel-import-workflow.md](intel-import-workflow.md) for the full schema and lifecycle state machines.

### Logs — logs/

```
logs/
├── audit-YYYYMMDD.log      # ir-log output + remote-session extension audit entries
└── remote-sessions/        # Per-session command logs: <session>-<timestamp>.log
```

Logs are append-only plain text. Mount `logs/` to durable host storage and ship to a SIEM for production deployments.

## Skills layer

Skills are markdown files and scripts that give the agent domain knowledge — which playbook to reach for, how to interpret findings, what to do next. Stored in `.pi/skills/`.

| Skill | Scripts | Content |
|-------|---------|---------|
| `gather-playbooks` | 61 | Collection scripts: Linux × 19, Windows × 28, macOS × 11, network-device × 3 |
| `host-ir-playbooks` | 12 | Host-centric IR: Linux × 2, Windows × 8, macOS × 2 |
| `containment-playbooks` | 12 | Evidence-first containment: Linux × 4, Windows × 4, macOS × 4 |
| `eradication-playbooks` | 13 | Persistence removal: Linux × 4, Windows × 4, macOS × 5 |
| `escalate-playbook` | 3 | Privilege escalation audit: Linux, Windows, macOS |
| `shell-commands` | reference docs | Native command references: LOLBAS, GTFOBins, persistence, lateral movement, containment |
| `nmap-playbooks` | reference docs | Network discovery, NSE script selection, safe scan design |

Target footprint: scripts use native OS commands. The agent reads scripts from the container filesystem and runs them inline via `remote_exec` where possible, or stages script text with `remote_upload` and cleanup when needed. Third-party tools and binaries stay in the harness.

## Persistence

Mount these directories to preserve state across container runs:

| Mount | What persists |
|-------|--------------|
| `-v "$PWD/logs:/opt/brjotskel/logs"` | Audit and per-session command logs |
| `-v "$PWD/.pi:/opt/brjotskel/.pi"` | Extensions, skills, settings, and local npm package cache |
| `-v "$PWD/workspace:/opt/brjotskel/workspace"` | Intel store (YAML files) and operator scratch space |

The intel store location defaults to `$BRJOTSKEL_INTEL_DIR` (container default: `/opt/brjotskel/workspace/intel`).

## Development workflow

Mounting `.pi/` makes extension and skill changes visible inside the container without rebuilding the image:

```sh
docker run --rm -it \
  -v "$PWD/logs:/opt/brjotskel/logs" \
  -v "$PWD/.pi:/opt/brjotskel/.pi" \
  -v "$PWD/workspace:/opt/brjotskel/workspace" \
  brjotskel:local
```

Rebuild the image only when changing `bin/`, `Dockerfile`, or base OS dependencies.

Run the test harness before pushing:

```sh
bash bin/test    # smoke check + inventory check + 41 Python unit tests + 95 Node tests
```

## Non-goals

- Operating against systems outside the authorized incident scope
- Running daemons or listeners inside the container
- Replacing mature SOAR or ticketing systems before they are needed
- Dropping tools or agents onto target hosts

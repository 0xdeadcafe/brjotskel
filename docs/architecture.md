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

A Debian bookworm-slim image pinned by digest. No daemons. `pi` launches by default as the non-root `brjotskel` user; `--entrypoint bash` gives a plain shell under the same user.

Runtime trust boundary: production Compose sets `no-new-privileges:true` and drops all Linux capabilities. The image bakes `.pi/` settings, extensions, skills, and nvim config as root-owned read-only code/config; the `.pi/` parent directory is sticky/group-writable only so pi can create transient settings lock directories. Runtime case-data writes are limited to `logs/`, `workspace/`, `/workspace`, and the `brjotskel` home directory for SSH/client caches and sessions. If an operation needs raw sockets (`ping`, SYN scans), add the required capability in a mission-specific override and record the exception.

Build-time dependency pins live in Docker `ARG` defaults and `requirements-harness.txt`: Python harness tools (Impacket, NetExec, Git deps, transitives), Node.js version plus release SHA-256, pi coding agent version, `pi-smart-fetch` version, PowerShell package version, and Rust toolchain. Bump them deliberately; do not use floating `latest`, unversioned npm, unpinned pip ranges, or Git HEAD for incident images.

Every image writes `/opt/brjotskel/BUILD-MANIFEST.json` during build. It records pinned inputs, Git/source metadata supplied by CI, runtime UID/GID, core tool versions, pi packages, selected file hashes, dpkg package inventory, pip freeze output, npm global packages, and known non-hermetic inputs. CI validates the manifest and uploads it with a generated CycloneDX JSON SBOM (`artifacts/brjotskel-sbom.cdx.json`).

Incident-release hardening target: build from controlled mirrors/caches for Debian apt, Microsoft apt, PyPI wheels/sdists, npm transitives, and rustup artifacts. Until that mirror/hash-locked release lane exists, treat CI SBOM + `BUILD-MANIFEST.json` as the evidence trail for exactly what landed in an image, not as a fully hermetic build guarantee.

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
| `ir-log` | Appends timestamped, hash-chained audit entries to `logs/audit-YYYYMMDD.log` |
| `ir-package` | Builds sensitive incident handoff archives with report, intel, logs, evidence, and SHA-256 manifests |
| `build-manifest` | Writes image provenance and package inventory to `/opt/brjotskel/BUILD-MANIFEST.json` during Docker build |
| `image-sbom` | Generates a CycloneDX JSON SBOM from a built Docker image for CI artifacts |
| `intel-snippet` | Generates normalized `intel_add(...)` payloads from gather output |
| `netexec-to-intel` | Converts NetExec success output into `intel_update(valid_on=...)` snippets |
| `check-playbook-inventory` | CI guard for README/docs playbook count drift |
| `check-playbook-contracts` | CI guard for target-side playbook metadata, safety contracts, and banned bootstrap patterns |
| `check-tool-inventory` | CI guard/generator for extension tool inventory drift |
| `clean-local` | Dry-run cleanup for ignored scratch/cache state |
| `curl`, `jq`, `git`, `python3`, `ripgrep`, `fd`, `neovim` | Support tools |

## Agent layer

`pi` is the AI agent. TypeScript extensions add IR-specific tools and persona context, loaded automatically from `.pi/extensions/`.

Generated tool inventory from `.pi/extensions/*.ts`; update with `bin/check-tool-inventory --write`.

<!-- BEGIN GENERATED TOOL INVENTORY -->
| Extension | Registered tools | Count |
|-----------|------------------|------:|
| `intel-scan.ts` | `intel_scan` | 1 |
| `intel-store.ts` | `intel_add`, `intel_get_cred`, `intel_map`, `intel_query`, `intel_summary`, `intel_timeline`, `intel_update` | 7 |
| `remote-session.ts` | `remote_connect`, `remote_disconnect`, `remote_exec`, `remote_relay`, `remote_relay_close`, `remote_sessions`, `remote_tunnel`, `remote_tunnel_close`, `remote_upload` | 9 |
| **Total** | `intel_add`, `intel_get_cred`, `intel_map`, `intel_query`, `intel_scan`, `intel_summary`, `intel_timeline`, `intel_update`, `remote_connect`, `remote_disconnect`, `remote_exec`, `remote_relay`, `remote_relay_close`, `remote_sessions`, `remote_tunnel`, `remote_tunnel_close`, `remote_upload` | **17** |
<!-- END GENERATED TOOL INVENTORY -->

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

Every `remote_exec` call is logged to `${BRJOTSKEL_LOG_DIR:-logs}/remote-sessions/` as both a human-readable session log (`<session>-YYYY-MM-DD.log`) and a structured hash-chained JSONL command record (`<session>-YYYY-MM-DD.jsonl`) containing command ID, timing, status, output SHA-256, byte/line counts, and taint state.

### intel-store.ts — 7 tools

| Tool | What it does |
|------|-------------|
| `intel_add` | Add a new entry with schema validation and provenance tracking. Auto-appends a timeline entry. |
| `intel_update` | Merge updates into an existing entry. Validates lifecycle transitions. Blocks reactivating terminal-status credentials without `force=true`. |
| `intel_query` | Query by host, credential, category, or keyword. |
| `intel_get_cred` | Retrieve a credential secret (password, hash, key path). Refuses terminal-status credentials. |
| `intel_timeline` | Add a manual timeline entry or view recent entries. |
| `intel_summary` | Counts and status breakdown across all categories. |
| `intel_map` | Text attack graph of hosts, credential blast radius, accounts, and pivots. |

The intel store normalizes arrays (union-merge by default) and validates schema on every write. Validation errors name the missing field and list allowed enum values. Every read-modify-write path takes a cross-process filesystem lock at `workspace/intel/.intel.lock`, so concurrent pi instances and `intel_scan` cannot silently clobber each other.

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

Files are created with restrictive permissions (0600, directory 0700) to protect credential material at rest. Writes use atomic temp-file rename plus a shared `.intel.lock` directory lock for cross-process coordination. The `intel_get_cred` tool refuses to return secrets for credentials with terminal statuses: `rotated`, `expired`, `revoked`, `disabled`, `inactive`, `invalid`.

See [intel-import-workflow.md](intel-import-workflow.md) for the full schema and lifecycle state machines.

### Logs — logs/

```
logs/
├── audit-YYYYMMDD.log      # ir-log output + remote-session extension audit entries
└── remote-sessions/        # Per-session command logs: <session>-<timestamp>.log
```

Logs are append-only by convention and hash-chained for tamper evidence. `ir-log` adds `entry_hash`/`previous_entry_hash`; remote command JSONL records do the same and store output SHA-256. Log write failures are fatal unless `BRJOTSKEL_ALLOW_DEGRADED_LOGGING=1` is explicitly set. Mount `logs/` to durable host storage and ship to a SIEM for production deployments.

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

| Mount | Mode | What persists |
|-------|------|--------------|
| `-v "$PWD/logs:/opt/brjotskel/logs"` | production writable | Audit and per-session command logs |
| `-v "$PWD/workspace:/opt/brjotskel/workspace"` | production writable | Intel store (YAML files) and operator scratch space |
| `-v "$PWD/.pi:/opt/brjotskel/.pi:ro"` | optional production read-only | Site-specific agent config/extensions/skills, frozen for the incident |
| `-v "$PWD/.pi:/opt/brjotskel/.pi"` | development only | Live-reload extensions, skills, settings, and local npm package cache |

The intel store location defaults to `$BRJOTSKEL_INTEL_DIR` (container default: `/opt/brjotskel/workspace/intel`). Host bind mounts must be writable by the container user; build with `BRJOTSKEL_UID=$(id -u)` and `BRJOTSKEL_GID=$(id -g)` when the default `1000:1000` does not match the operator workstation.

## Development workflow

Mounting `.pi/` writable makes extension and skill changes visible inside the container without rebuilding the image. That is dirty/dev-only because executable agent code comes from the host bind mount:

```sh
docker run --rm -it \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  -v "$PWD/logs:/opt/brjotskel/logs" \
  -v "$PWD/.pi:/opt/brjotskel/.pi" \
  -v "$PWD/workspace:/opt/brjotskel/workspace" \
  brjotskel:local
```

For production config overrides, bind `.pi/` read-only or rebuild the image. Rebuild the image only when changing `bin/`, `Dockerfile`, or base OS dependencies.

Run the test harness before pushing:

```sh
bash bin/test    # smoke check + strict TypeScript typecheck + inventory/tool-inventory/contract checks + 50 Python unit tests + 102 Node tests
```

## Non-goals

- Operating against systems outside the authorized incident scope
- Running daemons or listeners inside the container
- Replacing mature SOAR or ticketing systems before they are needed
- Dropping tools or agents onto target hosts

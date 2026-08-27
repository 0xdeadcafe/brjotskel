# brjotskel

[![CI](https://github.com/0xdeadcafe/brjotskel/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/0xdeadcafe/brjotskel/actions/workflows/ci.yml)

**AI-native incident response harness for environments without EDR.**

---

You get a call. A host is compromised. There's no EDR, the SIEM has gaps, and the attacker may still be active. You have SSH to one box and an unknown blast radius.

brjotskel gives you a containerized AI agent, 101 native-OS playbook scripts, and a structured intel store to land, assess, follow the credential trail, and eradicate completely — without dropping third-party binaries or tools on a target host.

---

## Why brjotskel?

Most IR tooling assumes either (a) an agent is already deployed, or (b) you have unlimited time to set one up. brjotskel assumes neither. It is built for the gap between "we have SSH credentials" and "the environment is fully recovered."

| Problem | How brjotskel addresses it |
|---------|---------------------------|
| No EDR on compromised hosts | 101 native-OS scripts — bash, PowerShell, sh — run inline or staged temporarily, using target-native commands only |
| Unknown blast radius | Structured intel store tracks hosts, credentials, and pivot paths; credential validation loop shows where each credential works |
| Attacker still active | Phase shortcuts (`/assess`, `/pursue`, `/contain`) let senior analysts move fast without ceremony |
| Multi-hop network topology | SSH tunnels, SOCKS proxies, and native TCP relays through any session type |
| Evidence lost when you act | Evidence-first containment and eradication scripts capture volatile state before every disruptive action |
| Investigation not reproducible | Every session, command, and finding is audit-logged; the intel store is the reconstruction artifact |

---

## Quick start

```sh
git clone https://github.com/0xdeadcafe/brjotskel
cd brjotskel
docker compose build
docker compose run --rm brjotskel
```

The container drops you into [pi](https://github.com/earendil-works/pi), an AI agent pre-configured with the Ghost IR persona, all playbooks, and the intel store. Describe the incident and it gets to work.

`logs/` and `workspace/` are mounted automatically — the intel store and audit logs persist across runs. The image runs as the non-root `brjotskel` user; if your host bind mounts are not writable by UID/GID `1000:1000`, set `BRJOTSKEL_UID=$(id -u)` and `BRJOTSKEL_GID=$(id -g)` before building.

**Shell access (no agent):**
```sh
docker compose run --rm shell
```

**Development (live-reload extensions and playbooks without rebuilding):**
```sh
docker compose run --rm dev
```

**Or without Compose:**
```sh
docker build \
  --build-arg BRJOTSKEL_UID="$(id -u)" \
  --build-arg BRJOTSKEL_GID="$(id -g)" \
  -t brjotskel:local .
docker run --rm -it \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  -v "$PWD/logs:/opt/brjotskel/logs" \
  -v "$PWD/workspace:/opt/brjotskel/workspace" \
  brjotskel:local
```

### Runtime hardening

Production Compose defaults run without root, deny new privileges, and drop Linux capabilities. The baked-in `.pi/` agent settings, extensions, skills, and nvim config are owned by root and read-only to the runtime user; `.pi/` itself allows only transient pi lock entries. Case data lives in writable `logs/` and `workspace/`. If you need raw-socket scans or `ping`, add capabilities explicitly in a local override and document why.

The `dev` Compose service is dirty by design: it bind-mounts executable `.pi/` code from the host for live reload. Use it for development only, not incident production runs. If production needs a local config override, mount it read-only (`./.pi:/opt/brjotskel/.pi:ro`) and keep case data in `logs/`/`workspace/`.

### Build reproducibility

The Docker build pins the base image digest and harness dependencies: Python tools in `requirements-harness.txt` (Impacket, NetExec, Git deps, transitives), Node.js tarball + SHA-256, pi, `pi-smart-fetch`, PowerShell, and the Rust toolchain used during build. Each image includes `/opt/brjotskel/BUILD-MANIFEST.json`; CI uploads that manifest plus a CycloneDX JSON SBOM. See [CONTRIBUTING.md](CONTRIBUTING.md#dependency-pinning-and-update-workflow) before bumping dependencies or building incident-release images.

---

## How it works

The AI agent doesn't just run commands — it reasons through the investigation. When you land on a host, it:

1. Opens a **persistent named remote session** (SSH, WinRM, or TCP/telnet)
2. Runs **platform-appropriate triage playbooks** without being told which ones to pick
3. Records every finding as **structured intel** — hosts, credentials, pivot paths, accounts — in a queryable YAML store
4. Follows the **credential trail**: recover → record → validate against other hosts → pivot

Target hosts see only native OS commands. Playbooks can be pasted inline or temporarily staged with cleanup; all third-party tools (`impacket`, `netexec`, `nmap`) run from the harness container.

### Target footprint

- **Allowed on targets:** native shell/PowerShell commands, OS administration tools already present, and temporary script text staging when inline execution is impractical.
- **Not allowed by default:** third-party binaries, package installs, downloaded tools, or persistent agents on targets.
- **Operator duty:** clean staged scripts, log every action, and record recovered intel with provenance.

---

## Core workflow

```
LAND → ASSESS → PURSUE → CONTAIN → ERADICATE → VERIFY
```

Phases overlap. You may be containing one host while still pursuing credentials on another. The intel store tracks state across phases so nothing gets lost between sessions.

### Phase shortcuts

Type these directly into the agent for fast-path access:

| Shortcut | What it produces |
|----------|-----------------|
| `/land` | Fast-access primitives, pivot options, immediate post-landing checklist |
| `/assess <session>` | Platform-specific first-look and follow-up triage commands for that session |
| `/pursue` | Live credential chase board — per-credential `netexec` commands against known hosts |
| `/contain <session>` | Evidence-first containment pack — process kill, C2 block, account disable |
| `/eradicate <session>` | Persistence removal workflow with verification steps |
| `/verify <session>` | Post-action checks: persistence gone, C2 silent, accounts locked, re-triage clean |
| `/scope` | Situational dump: active sessions, tunnels, intel counts, last 5 timeline events |
| `/map` | Text attack graph: host nodes, credential blast radius edges, pivot chains |
| `/report` | Incident brief: host status, credential rotation list, last 3 timeline events |
| `/brief` | Tactical intel brief: host status, credentials, pivots, open leads, next move |

Append `--prompt` to stage an editable agent prompt, e.g. `/assess web01 --prompt`.

### Agent tool inventory

Generated from `.pi/extensions/*.ts` by `bin/check-tool-inventory`; do not edit by hand.

<!-- BEGIN GENERATED TOOL INVENTORY -->
| Extension | Registered tools | Count |
|-----------|------------------|------:|
| `intel-scan.ts` | `intel_scan` | 1 |
| `intel-store.ts` | `intel_add`, `intel_get_cred`, `intel_map`, `intel_query`, `intel_summary`, `intel_timeline`, `intel_update` | 7 |
| `remote-session.ts` | `remote_connect`, `remote_disconnect`, `remote_exec`, `remote_relay`, `remote_relay_close`, `remote_sessions`, `remote_tunnel`, `remote_tunnel_close`, `remote_upload` | 9 |
| **Total** | `intel_add`, `intel_get_cred`, `intel_map`, `intel_query`, `intel_scan`, `intel_summary`, `intel_timeline`, `intel_update`, `remote_connect`, `remote_disconnect`, `remote_exec`, `remote_relay`, `remote_relay_close`, `remote_sessions`, `remote_tunnel`, `remote_tunnel_close`, `remote_upload` | **17** |
<!-- END GENERATED TOOL INVENTORY -->

> **New to the tool?** Start with [docs/getting-started.md](docs/getting-started.md) for a first-incident walkthrough.
> For a detailed end-to-end scenario, see [docs/scenario-walkthrough.md](docs/scenario-walkthrough.md).

---

## Playbooks

101 native-OS scripts. They use commands already present on the target OS; run them inline when possible or temporarily stage script text with cleanup when needed.

| Category | Linux | Windows | macOS | Network devices |
|----------|------:|--------:|------:|----------------:|
| Gather | 19 | 28 | 11 | 3 |
| Host IR | 2 | 8 | 2 | — |
| Containment | 4 | 4 | 4 | — |
| Eradication | 4 | 4 | 5 | — |
| Privilege escalation | 1 | 1 | 1 | — |

The gather scripts cover: credentials, cloud tokens, SSH keys, persistence, network, AD/domain, browser artifacts, USB history, PSReadLine, DNS cache, LSASS, prefetch, Kerberos events, AppLocker, reachability probes, and more.

Credential gather output is restricted evidence. Some credential scripts redact obvious values by default; set `BRJOTSKEL_REVEAL_SECRETS=1` only when raw material is needed for validation/import. Session logs and `ir-package` archives may still contain raw secrets until all touched credentials are rotated or revoked.

See [docs/playbooks.md](docs/playbooks.md) for the complete script inventory with per-script descriptions.

---

## Intel tracking

Every finding is recorded in a structured YAML store at `workspace/intel/`. The store persists across container restarts, supports lifecycle-aware status transitions, and gates credential retrieval on status — a rotated credential cannot be retrieved even if you try.

```text
# Record a host as you land
intel_add(category="host", id="web01",
  data="ip: 10.10.10.5\nplatform: linux\nstatus: compromised\nsource:\n  method: authorized scope",
  summary="Initial foothold — confirmed compromised")

# Find all credentials valid on a specific host
intel_query(query_type="for_host", target="dc01")

# Move a host through its lifecycle
intel_update(category="host", id="web01",
  fields="status: contained\nnotes: C2 185.x.x.x blocked, PID 4523 killed",
  summary="web01 contained")

# Full investigation picture
intel_summary()
intel_timeline(action="view")
```

`bin/intel-snippet` generates ready-to-paste `intel_add(...)` calls from gather playbook output — handling schema validation and required provenance fields automatically. See [docs/intel-import-workflow.md](docs/intel-import-workflow.md).

---

## Container toolchain

| Tool | Purpose |
|------|---------|
| `ssh`, `sshpass` | Key and password SSH, ProxyJump chains, port forwards |
| `pwsh` | PowerShell 7 remoting (WinRM) |
| `nmap`, `ncat`, `nc` | Service discovery, relay setup |
| `proxychains4` | Route any tool through a SOCKS pivot |
| `secretsdump.py` | Remote SAM/LSASS/NTDS credential dump over SMB |
| `psexec.py`, `wmiexec.py`, `smbexec.py` | Lateral movement with recovered credentials |
| `ntlmrelayx.py` | NTLM relay |
| `netexec` | Credential validation at scale — SMB, WinRM, SSH, MSSQL |
| `ir-log` | Audit logger — timestamped, hash-chained entries to `logs/audit-YYYYMMDD.log` |
| `ir-search` | `fzf`-based search across audit/session logs; Enter saves selected hits to `logs/ir-search-hits.txt` |
| `ir-report` | Incident report generator — renders intel store to markdown or JSON |
| `ir-package` | Sensitive incident handoff package — report, intel, logs, evidence, SHA-256 manifests |
| `build-manifest` | Image provenance generator for `/opt/brjotskel/BUILD-MANIFEST.json` |
| `image-sbom` | CycloneDX JSON SBOM generator for built Docker images |
| `intel-snippet` | Generate normalized `intel_add(...)` payloads from gather output |
| `netexec-to-intel` | Convert NetExec success output into `intel_update(valid_on=...)` snippets |
| `check-playbook-inventory` | CI guard for README/docs playbook count drift |
| `check-playbook-contracts` | CI guard for target-side playbook metadata, safety contracts, and banned bootstrap patterns |
| `check-tool-inventory` | CI guard/generator for extension tool inventory drift |
| `clean-local` | Dry-run cleanup for ignored scratch/cache state; preserves logs/workspace by default |
| `curl`, `jq`, `git`, `python3`, `ripgrep`, `fd`, `neovim` | General support |

---

## Platform coverage

| Platform | Access | Gather | IR | Privesc | Pivoting |
|----------|--------|-------:|---:|---------|---------|
| Linux | SSH | 19 | 2 | ✓ | SSH tunnels, socat/ncat/nc relays |
| Windows | WinRM, SSH | 28 | 8 | ✓ | netsh portproxy, ncat relays |
| macOS | SSH | 11 | 2 | ✓ | SSH tunnels, socat/ncat relays |
| Network devices | SSH, telnet | 3 | — | — | — |

---

## Repository layout

```
.pi/extensions/     Agent extensions: sessions, tunnels, relays, intel store, phase shortcuts
.pi/skills/         All playbooks and reference docs (per-platform subdirectories)
.pi/prompts/        /brief and /incident prompt templates
bin/                ir-log, ir-search, ir-report, ir-package, build-manifest, image-sbom, intel-snippet, netexec-to-intel, check-playbook-inventory, check-playbook-contracts, check-tool-inventory, clean-local, smoke-check, test
docs/               Guides, runbooks, and reference documentation
logs/               Audit and per-session command logs (mount to persist)
workspace/          Intel store YAML and operator scratch space (mount to persist)
Dockerfile          Container image
CONSTITUTION.md     Safety model and rules of engagement
CONTRIBUTING.md     How to add playbooks, extend the agent, and run tests
```

---

## Safety model

brjotskel operates under an explicit rules of engagement framework. See [CONSTITUTION.md](CONSTITUTION.md).

**Short version:** only operate within the authorized incident scope, collect evidence before taking destructive action, log every pivot and credential harvest, never drop third-party tools or binaries on target hosts.

---

## Documentation

| Doc | Purpose |
|-----|---------|
| [docs/getting-started.md](docs/getting-started.md) | First-incident walkthrough — zero to triage in under five minutes |
| [docs/scenario-walkthrough.md](docs/scenario-walkthrough.md) | Full incident example: Linux web server → lateral movement → DC |
| [docs/runbook.md](docs/runbook.md) | Complete operational reference — phases, commands, decision heuristics |
| [docs/playbooks.md](docs/playbooks.md) | Full script inventory with per-script descriptions |
| [docs/intel-import-workflow.md](docs/intel-import-workflow.md) | Intel store schema, lifecycle states, and `intel-snippet` templates |
| [docs/relay-pivoting.md](docs/relay-pivoting.md) | Pivot decision tree and method reference |
| [docs/architecture.md](docs/architecture.md) | Component design, extension API, data layer |
| [CONSTITUTION.md](CONSTITUTION.md) | Safety model and rules of engagement |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contributing playbooks, extensions, tests |

---

## Local cleanup

```sh
bin/clean-local              # dry-run: temp/, caches, __pycache__, *.pyc
bin/clean-local --execute    # delete selected generated/scratch paths
```

`logs/` and `workspace/` are protected by default. Use `--include-case-data --execute` only when intentionally clearing local incident state.

---

## CI

```yaml
- run: bash bin/test        # smoke check + strict TypeScript typecheck + inventory/tool-inventory/contract checks + 50 Python unit tests + 102 Node tests
- run: docker build -t brjotskel:ci .
```

[![CI](https://github.com/0xdeadcafe/brjotskel/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/0xdeadcafe/brjotskel/actions/workflows/ci.yml)

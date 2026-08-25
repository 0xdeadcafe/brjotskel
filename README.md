# brjotskel

[![CI](https://github.com/0xdeadcafe/brjotskel/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/0xdeadcafe/brjotskel/actions/workflows/ci.yml)

**AI-native incident response harness for environments without EDR.**

---

You get a call. A host is compromised. There's no EDR, the SIEM has gaps, and the attacker may still be active. You have SSH to one box and an unknown blast radius.

brjotskel gives you a containerized AI agent, 96 native-OS playbook scripts, and a structured intel store to land, assess, follow the credential trail, and eradicate completely — without dropping a single binary on a target host.

---

## Why brjotskel?

Most IR tooling assumes either (a) an agent is already deployed, or (b) you have unlimited time to set one up. brjotskel assumes neither. It is built for the gap between "we have SSH credentials" and "the environment is fully recovered."

| Problem | How brjotskel addresses it |
|---------|---------------------------|
| No EDR on compromised hosts | 96 native-OS scripts — bash, PowerShell, sh — that collect everything without uploading anything |
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
docker build -t brjotskel:local .

docker run --rm -it \
  -v "$PWD/logs:/opt/brjotskel/logs" \
  -v "$PWD/workspace:/opt/brjotskel/workspace" \
  brjotskel:local
```

The container drops you into [pi](https://github.com/earendil-works/pi), an AI agent pre-configured with the Ghost IR persona, all playbooks, and the intel store. Describe the incident and it gets to work.

Mount `logs/` and `workspace/` so audit logs and the intel store persist across container restarts.

**Shell access (no agent):**
```sh
docker run --rm -it --entrypoint bash \
  -v "$PWD/logs:/opt/brjotskel/logs" \
  -v "$PWD/workspace:/opt/brjotskel/workspace" \
  brjotskel:local
```

**Development (live-reload extensions and playbooks):**
```sh
docker run --rm -it \
  -v "$PWD/logs:/opt/brjotskel/logs" \
  -v "$PWD/.pi:/opt/brjotskel/.pi" \
  -v "$PWD/workspace:/opt/brjotskel/workspace" \
  brjotskel:local
```

---

## How it works

The AI agent doesn't just run commands — it reasons through the investigation. When you land on a host, it:

1. Opens a **persistent named remote session** (SSH, WinRM, or TCP/telnet)
2. Runs **platform-appropriate triage playbooks** without being told which ones to pick
3. Records every finding as **structured intel** — hosts, credentials, pivot paths, accounts — in a queryable YAML store
4. Follows the **credential trail**: recover → record → validate against other hosts → pivot

Target hosts see only native OS commands. All third-party tools (`impacket`, `netexec`, `nmap`) run from the harness container.

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
| `/brief` | Tactical intel brief: host status, credentials, pivots, open leads, next move |

Append `--prompt` to stage an editable agent prompt, e.g. `/assess web01 --prompt`.

> **New to the tool?** Start with [docs/getting-started.md](docs/getting-started.md) for a first-incident walkthrough.
> For a detailed end-to-end scenario, see [docs/scenario-walkthrough.md](docs/scenario-walkthrough.md).

---

## Playbooks

96 native-OS scripts — nothing is uploaded to target hosts. All use only commands already present on the target OS.

| Category | Linux | Windows | macOS | Network devices |
|----------|------:|--------:|------:|----------------:|
| Gather | 19 | 27 | 10 | 3 |
| Host IR | 2 | 8 | 2 | — |
| Containment | 4 | 3 | 3 | — |
| Eradication | 4 | 4 | 5 | — |
| Privilege escalation | 1 | 1 | 1 | — |

The gather scripts cover: credentials, cloud tokens, SSH keys, persistence, network, AD/domain, browser artifacts, USB history, PSReadLine, DNS cache, LSASS, prefetch, Kerberos events, AppLocker, reachability probes, and more.

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
| `ir-log` | Audit logger — timestamped entries to `logs/audit-YYYYMMDD.log` |
| `ir-search` | `fzf`-based interactive search across all audit and session logs |
| `ir-report` | Incident report generator — renders intel store to markdown or JSON |
| `intel-snippet` | Generate normalized `intel_add(...)` payloads from gather output |
| `curl`, `jq`, `git`, `python3`, `ripgrep`, `fd`, `neovim` | General support |

---

## Platform coverage

| Platform | Access | Gather | IR | Privesc | Pivoting |
|----------|--------|-------:|---:|---------|---------|
| Linux | SSH | 19 | 2 | ✓ | SSH tunnels, socat/ncat/nc relays |
| Windows | WinRM, SSH | 27 | 8 | ✓ | netsh portproxy, ncat relays |
| macOS | SSH | 10 | 2 | ✓ | SSH tunnels, socat/ncat relays |
| Network devices | SSH, telnet | 3 | — | — | — |

---

## Repository layout

```
.pi/extensions/     Agent extensions: sessions, tunnels, relays, intel store, phase shortcuts
.pi/skills/         All playbooks and reference docs (per-platform subdirectories)
.pi/prompts/        /brief and /incident prompt templates
bin/                ir-log, ir-search, intel-snippet, smoke-check, test
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

**Short version:** only operate within the authorized incident scope, collect evidence before taking destructive action, log every pivot and credential harvest, never drop tools on target hosts.

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

## CI

```yaml
- run: bash bin/test        # smoke check + 26 Python unit tests + 88 Node tests
- run: docker build -t brjotskel:ci .
```

[![CI](https://github.com/0xdeadcafe/brjotskel/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/0xdeadcafe/brjotskel/actions/workflows/ci.yml)

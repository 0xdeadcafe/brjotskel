# brjotskel

[![CI](https://github.com/0xdeadcafe/brjotskel/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/0xdeadcafe/brjotskel/actions/workflows/ci.yml)

**AI-native incident response harness for environments without EDR.**

You get a call. A host is compromised. There's no EDR, the SIEM has gaps, and the attacker may still be active. You have SSH to one box and an unknown blast radius. This container gives you the tooling, playbooks, and AI agent to land, assess, follow the credential trail across the network, and eradicate completely — without dropping a single binary on a target host.

---

## Quick start

```sh
docker build -t brjotskel:local .

docker run --rm -it \
  -v "$PWD/logs:/opt/brjotskel/logs" \
  -v "$PWD/.pi:/opt/brjotskel/.pi" \
  -v "$PWD/workspace:/opt/brjotskel/workspace" \
  brjotskel:local
```

The container drops you directly into [pi](https://github.com/earendil-works/pi), an AI coding agent with IR tools built in. Describe what you're investigating and it gets to work. Mount `logs/` and `workspace/` for persistence across runs.

**Shell access:**
```sh
docker run --rm -it --entrypoint bash \
  -v "$PWD/logs:/opt/brjotskel/logs" \
  -v "$PWD/.pi:/opt/brjotskel/.pi" \
  -v "$PWD/workspace:/opt/brjotskel/workspace" \
  brjotskel:local
```

**Validate changes:**
```sh
bash bin/test
```

---

## How it works

The AI agent doesn't just run commands — it reasons through the investigation. When you connect to a compromised host, it:

- Opens and maintains **persistent named remote sessions** over SSH, WinRM, or TCP/telnet
- Runs **platform-appropriate triage playbooks** without being told which ones to pick
- Records every finding as **structured intel** — hosts, credentials, pivot paths, accounts — in a queryable YAML store that persists across container restarts
- Follows the **credential trail automatically**: recover → record → validate against other hosts → pivot

Target hosts only ever see native OS commands. All third-party tools (`impacket`, `netexec`, `nmap`) run from the harness container.

---

## Core workflow

```
LAND → ASSESS → PURSUE → CONTAIN → ERADICATE → VERIFY
```

Phases overlap in practice. You might be containing one host while still pursuing credentials on another.

### Phase shortcuts

For senior responders moving fast, type these directly into the agent:

| Shortcut | What it produces |
|----------|-----------------|
| `/land` | Fast-access primitives, pivot options, immediate post-landing checklist |
| `/assess <session>` | Platform-specific first-look and follow-up triage commands for that session |
| `/pursue` | Credential recovery, validation, and pivot chase-board commands |
| `/contain <session>` | Evidence-first containment command pack — process kill, C2 block, account disable |
| `/eradicate <session>` | Persistence removal workflow with verification steps |
| `/verify <session>` | Post-action checks: persistence gone, C2 silent, accounts locked, re-triage clean |

Append `--prompt` to stage an editable agent prompt instead of displaying the shortcut inline, e.g. `/assess web01 --prompt`.

### Example: following a credential trail

```
# Land on the first confirmed compromised host
remote_connect(protocol="ssh", target="root@10.10.10.5", name="web01", password="...")
intel_add(category="host", id="web01", data="ip: 10.10.10.5\nplatform: linux\nstatus: compromised\nsource:\n  method: authorized scope")

# 30-second first look
/assess web01

# Recover credentials
remote_exec(session="web01", command="<linux/hashdump.sh>")
remote_exec(session="web01", command="<linux/ssh-keys.sh>")
remote_exec(session="web01", command="<linux/enum-credentials.sh>")

# Record findings with provenance
intel_add(category="credential", id="deploy-key",
  data="type: ssh-key\nusername: deploy\nkey_file: workspace/intel/keys/deploy-ed25519\nstatus: active\nsource:\n  host: web01\n  method: ssh-keys.sh\n  path: /home/deploy/.ssh/id_ed25519")

# Validate at scale from the harness
netexec ssh 10.10.20.0/24 -u deploy --key workspace/intel/keys/deploy-ed25519

# Pivot to the next host
remote_connect(protocol="ssh", target="deploy@10.10.20.10", name="db01",
  identity="workspace/intel/keys/deploy-ed25519")
```

### Pivoting when direct access is blocked

```
# SSH tunnel for SOCKS-based multi-tool routing
remote_tunnel(type="dynamic", via="root@web01", local_port=1080)
# proxychains netexec smb 10.10.20.0/24 -u admin -H <hash>

# Native relay through a Windows pivot with no OpenSSH
remote_relay(session="dc01", target_host="10.10.30.10", target_port=445, listen_port=44450)
# netexec smb 10.10.10.20 --port 44450 -u sa -H <hash>

# Multi-hop: harness → web01 (SSH) → dc01 (WinRM) → sql01 (SMB only, unreachable from harness)
remote_tunnel(type="local", via="root@web01", local_port=5985, remote_host="dc01", remote_port=5985)
remote_connect(protocol="winrm", target="administrator@localhost", port=5985, name="dc01")
remote_relay(session="dc01", target_host="10.10.30.10", target_port=445, listen_port=44450)
remote_tunnel(type="local", via="root@web01", local_port=44450, remote_host="dc01", remote_port=44450)
```

| Pivot method | When to use |
|--------------|------------|
| SSH ProxyJump | All hops support SSH |
| SSH local forward | Reach a specific service (WinRM, SMB) through an SSH pivot |
| SSH dynamic SOCKS | Route many tools through one pivot |
| `remote_relay` — socat/ncat | Linux pivot with no SSH tunneling available |
| `remote_relay` — netsh portproxy | Windows pivot without OpenSSH |
| `remote_relay` — nc fifo | Minimal Linux environment, last resort |

See [docs/relay-pivoting.md](docs/relay-pivoting.md) for the full decision tree and chaining examples.

---

## Triage playbooks

61 platform-specific scripts built into the container. All use native OS commands — nothing is uploaded to the target.

### Linux — 16 gather scripts

| Script | Category | What it collects |
|--------|----------|-----------------|
| `first-look.sh` | situational | Live sessions, outbound connections, staging areas (`/tmp`, `/dev/shm`), immediate persistence indicators |
| `hashdump.sh` | credentials | `/etc/shadow`, `/etc/passwd`, `opasswd` |
| `ssh-keys.sh` | credentials | SSH private keys, `authorized_keys`, `known_hosts` across all users |
| `enum-credentials.sh` | credentials | AWS keys, Docker credentials, `.env` files, shell history tokens |
| `enum-user-history.sh` | evidence | Shell history patterns, suspicious execution, SSH config references |
| `ansible-triage.sh` | pivot | Ansible inventory targets, private key references, SSH host hints |
| `enum-vpn-creds.sh` | pivot | OpenVPN, WireGuard, NetworkManager VPN profiles — endpoints and auth references |
| `enum-cifs-creds.sh` | pivot | SMB/CIFS mounts, credential files, target shares |
| `enum-network.sh` | network | Interfaces, routes, iptables rules, live connections, DNS, ARP |
| `enum-persistence.sh` | persistence | Crons, systemd units, rc.local, shell profiles, timers |
| `enum-system.sh` | system | Users, packages, services, SUID binaries, kernel |
| `enum-configs.sh` | system | Service configs (Apache, MySQL, sshd, Samba, etc.) |
| `enum-containers.sh` | system | Docker/Podman containers, images, volumes, networks |
| `enum-protections.sh` | security | EDR/AV/IDS detection, kernel hardening state |
| `privesc-check.sh` | privesc | `sudo -l`, SUID, capabilities, writable privileged paths |
| `triage.sh` | meta | One-shot runner combining all core gather categories |

### Windows — 24 gather scripts

| Script | Category | What it collects |
|--------|----------|-----------------|
| `first-look.ps1` | situational | Live sessions, connections, suspicious tasks/services, Defender state |
| `hashdump.ps1` | credentials | SAM/SYSTEM hive export |
| `enum-credentials.ps1` | credentials | Credential Manager, vault, WiFi profiles, cached logons |
| `enum-unattend-autologon.ps1` | credentials | Unattend/sysprep files, autologon registry values, plaintext credential hints |
| `psreadline-history.ps1` | credentials | PowerShell command history across all user profiles, suspicious command hits |
| `putty-sessions.ps1` | pivot | PuTTY saved sessions, stored SSH host keys, key-file paths, Pageant presence |
| `enum-network.ps1` | network | Interfaces, routes, firewall rules, live connections, DNS, shares |
| `enum-dnscache.ps1` | network | DNS client cache entries, suspicious destination hints |
| `enum-rasvpn-events.ps1` | network | RAS/VPN client and server connection and authentication events |
| `enum-system.ps1` | system | Users, groups, services, scheduled tasks, installed software |
| `enum-prefetch.ps1` | evidence | Prefetch execution artifacts, suspicious binary names |
| `enum-persistence.ps1` | persistence | Run keys, services, tasks, WMI subscriptions, startup folders |
| `enum-artifacts.ps1` | evidence | Remote-admin, transfer, script, and persistence artifact locations |
| `enum-browser-artifacts.ps1` | evidence | Browser profiles, bookmarks, downloads, typed URLs, admin-console clues |
| `enum-kerberos-events.ps1` | evidence | Kerberos 4769 activity, weak-encryption ticket indicators |
| `enum-applocker-events.ps1` | evidence | AppLocker allow/block events, LOLBIN execution hints |
| `enum-protections.ps1` | security | AV/EDR status, AppLocker, AMSI, firewall state |
| `enum-av-exclusions.ps1` | security | Defender/antimalware/SEP exclusion paths, processes, extensions |
| `enum-usb-history.ps1` | evidence | USB storage, mounted-drive, and removable-volume history |
| `enum-ad.ps1` | domain | Domain info, trusts, SPNs, privileged groups, GPOs |
| `enum-ad-users.ps1` | domain | AD user inventory, ASREP-roastable accounts, service-like users |
| `enum-ad-groups.ps1` | domain | Privileged and operationally relevant domain groups and members |
| `enum-ad-spns.ps1` | domain | SPN-bearing user/computer accounts, Kerberoastable targets |
| `enum-ad-computers.ps1` | domain | Domain computer inventory, OS fields, naming clues, managedBy hints |

### macOS — 9 gather scripts

| Script | Category | What it collects |
|--------|----------|-----------------|
| `first-look.sh` | situational | Live sessions, outbound connections, launchd persistence indicators, security state |
| `enum-system.sh` | system | `sw_vers`, hardware/software profile, users, launchd jobs, FileVault/SIP state |
| `enum-network.sh` | network | Interfaces, routes, DNS, proxies, Wi-Fi preferences, live connections, ARP |
| `enum-persistence.sh` | persistence | LaunchDaemons, LaunchAgents, shell/profile hooks, autologin, cron artifacts |
| `enum-credentials.sh` | credentials | Keychain metadata, SSH/GPG material, shell history, cloud tokens, autologin hints |
| `enum-remote-access-artifacts.sh` | pivot | Wi-Fi details, VNC/screensharing, Safari last session, SSH remote-access traces |
| `enum-launchd.sh` | persistence | Loaded `launchctl` jobs, plist labels, programs, watch paths, logging paths |
| `enum-unified-logs.sh` | logs | `log show` output for launchd, auth, exec/spawn, and network activity |
| `enum-browser-artifacts.sh` | evidence | Safari, Chrome, Firefox artifact locations, recent session/history metadata |

### Host IR playbooks — 9 scripts

Focused compromise investigation, distinct from broad collection. Use these when you need to prove or disprove attacker presence on a specific host.

| Platform | Script | Purpose |
|----------|--------|---------|
| Linux | `initial-assessment.sh` | Artifact-first compromise investigation, attacker TTP reconstruction |
| macOS | `live-response.sh` | Live-response evidence collection |
| Windows | `initial-assessment.ps1` | Artifact-first host IR |
| Windows | `persistence-hunt.ps1` | Deep persistence enumeration |
| Windows | `eventlog-hunt.ps1` | High-signal event log threat hunting |
| Windows | `eventlog-hunt-lite.ps1` | Fast event log sweep (no Sysmon required) |
| Windows | `sysmon-hunt.ps1` | Sysmon-focused event hunting |
| Windows | `powershell-reconstruction.ps1` | Reconstruct attacker PowerShell activity from logs |
| Windows | `triage.ps1` | Combined host IR triage runner |

---

## Intel tracking

Every finding is recorded in a structured YAML store at `workspace/intel/`. The store persists across container restarts and supports lifecycle-aware status transitions — a compromised host becomes contained becomes cleared; a credential becomes rotated and can no longer be retrieved.

```
# Record a credential with full provenance
intel_add(category="credential", id="admin-ntlm",
  data="type: ntlm-hash\nusername: admin\nsecret: aad3b...\nstatus: active\nvalid_on:\n  - dc01\nsource:\n  host: web01\n  method: secretsdump\n  path: C:\\Windows\\NTDS\\ntds.dit",
  summary="Domain admin NTLM recovered from web01")

# Query what access you have to a specific host
intel_query(query_type="for_host", target="dc01")

# Follow all active credentials
intel_query(query_type="all_credentials")

# Update lifecycle state after containment
intel_update(category="host", id="web01",
  fields="status: contained\nnotes: C2 185.x.x.x blocked, PID 4523 killed",
  summary="web01 contained")

# Force credential rotation record
intel_update(category="credential", id="admin-ntlm",
  fields="status: rotated", summary="Reset forced by identity team post-incident")

# See the full investigation picture
intel_summary()
intel_timeline(action="view")
```

**`bin/intel-snippet`** generates normalized `intel_add(...)` calls from gather playbook findings — handling YAML quoting, required provenance fields, and schema validation. Templates cover PuTTY sessions, Ansible inventories, PSReadLine hits, DNS cache entries, AD accounts, VPN configs, RDP artifacts, and more.

See [docs/intel-import-workflow.md](docs/intel-import-workflow.md).

---

## Container toolchain

Everything runs from the harness. Nothing is installed on target hosts.

| Tool | Purpose |
|------|---------|
| `ssh`, `sshpass` | Key and password SSH, ProxyJump chains, port forwards |
| `pwsh` | PowerShell 7, WinRM remoting |
| `nmap`, `ncat`, `nc` | Service discovery, relay setup |
| `proxychains4` | Route any tool through a SOCKS pivot |
| `secretsdump.py` | Remote SAM/LSASS/NTDS dump over SMB |
| `psexec.py`, `wmiexec.py`, `smbexec.py` | Lateral movement with recovered credentials |
| `ntlmrelayx.py` | NTLM relay |
| `netexec` | Credential validation at scale — SMB, WinRM, SSH, MSSQL |
| `ir-log` | Operator audit logger — appends timestamped entries to `logs/audit-YYYYMMDD.log` |
| `intel-snippet` | Generate normalized `intel_add(...)` payloads from gather playbook findings |
| `curl`, `jq`, `git`, `python3`, `ripgrep`, `fd`, `neovim` | General support |

---

## Repository layout

```text
.pi/extensions/     remote-session.ts — sessions, tunnels, relays, phase shortcuts
                    intel-store.ts    — intel add/update/query/timeline tools
.pi/skills/         triage and IR playbooks (linux/, windows/, macos/ per skill)
bin/                ir-log, intel-snippet, smoke-check, test
docs/               architecture, runbooks, and workflow references
logs/               local audit and session logs (mount to persist)
workspace/          intel store and operator scratch space (mount to persist)
Dockerfile          container image definition
CONSTITUTION.md     safety model and rules of engagement
```

---

## Platform coverage

| Platform | Access | Gather scripts | IR playbooks | Privesc | Pivoting |
|----------|--------|---------------|-------------|---------|---------|
| Linux | SSH | 16 | 1 | ✓ | SSH tunnels, socat/ncat/nc relays |
| Windows | WinRM, SSH | 24 | 7 | ✓ | netsh portproxy, ncat relays |
| macOS | SSH | 9 | 1 | ✓ | SSH tunnels, socat/ncat relays |
| Network devices | SSH, telnet | CLI (operator-driven) | — | — | — |

TCP/telnet targets accept `host:port`, `[IPv6]:port`, or explicit `port=`. No-banner services are treated as connected when the socket stays open.

---

## CI

GitHub Actions runs the full test harness and a Docker smoke build on every push.

```yaml
# .github/workflows/ci.yml
- run: bash bin/test        # smoke check + 9 Python unit tests + 45 Node tests
- run: docker build -t brjotskel:ci .
```

---

## Safety model

See [CONSTITUTION.md](CONSTITUTION.md).

Operate only within the authorized incident scope. Collect evidence before taking destructive action. Log every pivot, credential harvest, and eradication step with enough context to reconstruct what happened. Never drop tools on target hosts — the harness container carries everything.

---

## Documentation

| Doc | Purpose |
|-----|---------|
| [docs/analyst-runbook.md](docs/analyst-runbook.md) | Operational workflow — phases, decision heuristics, full command quick-reference |
| [docs/relay-pivoting.md](docs/relay-pivoting.md) | Pivot decision tree and method reference when SSH tunneling isn't available |
| [docs/intel-import-workflow.md](docs/intel-import-workflow.md) | Templates for normalizing gather findings into structured intel |
| [docs/architecture.md](docs/architecture.md) | Component design and operational workflow detail |
| [docs/analyst-improvement-plan.md](docs/analyst-improvement-plan.md) | Contributing guide, known gaps, and roadmap |
| [CONSTITUTION.md](CONSTITUTION.md) | Safety model and rules of engagement |

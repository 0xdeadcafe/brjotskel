---
name: gather-playbooks
zero_key: false
description: "Post-exploitation gather playbooks for compromised host triage. Native OS commands only — no binaries uploaded. Covers credential harvesting, system enumeration, network mapping, persistence detection, and security tool identification across Linux, Windows, and macOS."
---

# Gather Playbooks — Post-Exploitation Host Triage

Structured gather scripts that run native OS commands on compromised hosts to enumerate credentials, system state, network configuration, persistence mechanisms, and installed security tools across Linux, Windows, and macOS.

## Purpose and scope

- **Purpose**: Provide ready-to-run triage scripts for compromised hosts during active IR. Each script collects a specific category of information using only commands native to the target OS.
- **Scope**: Read-only enumeration by default. Scripts run over existing `remote_exec` sessions or via `remote_upload`. Output is structured text designed for parsing into `intel_add` entries.

## ⚠️ Core Principles

1. **Native commands only** — Every script uses native OS commands or commonly available built-in administrative tooling already present on the target. No curl downloads, no pip installs, no binary uploads.
2. **Read-only** — Gather scripts do not modify the system. Exception: `hashdump` on Windows saves registry hives (documented clearly).
3. **Execution cleanup** — When scripts are uploaded for execution, remove them afterward as part of the workflow.
4. **Minimal footprint** — Scripts should stay small and fast, and produce structured text output.
5. **No persistent state** — Scripts don't write temp files, logs, or markers on target.

## Use when

- Initial triage of a newly confirmed compromised host
- Following attacker's credential trail across systems
- Mapping what security tools the attacker had to evade
- Identifying persistence mechanisms for eradication
- Discovering lateral movement paths (SSH keys, cached creds, network neighbors)

## Do not use when

- The host is not confirmed compromised and authorized for investigation
- You need real-time monitoring (use EDR/agent-based tools)
- You need memory forensics (use dedicated memory acquisition)

## Playbook Inventory

### Linux

| Script | Category | What It Collects |
|--------|----------|------------------|
| `linux/hashdump.sh` | credentials | /etc/shadow, /etc/passwd, opasswd |
| `linux/ssh-keys.sh` | credentials | SSH private keys, authorized_keys, known_hosts |
| `linux/enum-credentials.sh` | credentials | AWS keys, Docker creds, .env files, history, tokens |
| `linux/enum-user-history.sh` | evidence | Shell history files, suspicious execution patterns, SSH config references |
| `linux/ansible-triage.sh` | pivot | Ansible config, inventory targets, private-key references, SSH host hints |
| `linux/enum-vpn-creds.sh` | pivot | OpenVPN, WireGuard, NetworkManager VPN profiles, endpoint and auth references |
| `linux/enum-cifs-creds.sh` | pivot | SMB/CIFS mounts, credential files, target shares, history hits |
| `linux/enum-network.sh` | network | Interfaces, routes, iptables, connections, DNS, ARP |
| `linux/enum-system.sh` | system | Users, packages, services, crons, SUID, kernel |
| `linux/enum-configs.sh` | system | Service configs (apache, mysql, sshd, samba, etc.) |
| `linux/enum-protections.sh` | security | EDR/AV/IDS detection, kernel hardening state |
| `linux/enum-persistence.sh` | persistence | Crons, systemd units, rc.local, shell profiles, timers |
| `linux/enum-containers.sh` | system | Docker/podman containers, images, volumes, networks |
| `linux/privesc-check.sh` | privesc | sudo -l, SUID, capabilities, writable paths |
| `linux/triage.sh` | meta | One-shot Linux triage runner that combines the core gather categories |

### Windows

| Script | Category | What It Collects |
|--------|----------|------------------|
| `windows/hashdump.ps1` | credentials | SAM/SYSTEM hive export (requires admin) |
| `windows/enum-credentials.ps1` | credentials | Credential Manager, vault, WiFi, cached logons |
| `windows/enum-unattend-autologon.ps1` | credentials | Unattend/sysprep files, autologon registry values, and plaintext credential hints |
| `windows/psreadline-history.ps1` | credentials | PowerShell command history across user profiles, plus suspicious command hits |
| `windows/putty-sessions.ps1` | pivot | PuTTY saved sessions, stored SSH host keys, referenced key-file paths, Pageant presence |
| `windows/enum-network.ps1` | network | Interfaces, routes, firewall, connections, DNS, shares |
| `windows/enum-dnscache.ps1` | network | DNS client cache entries and suspicious destination hints |
| `windows/enum-rasvpn-events.ps1` | network | Microsoft RemoteAccess / RAS VPN client and server connection/authentication events |
| `windows/enum-system.ps1` | system | Users, groups, services, scheduled tasks, installed SW |
| `windows/enum-prefetch.ps1` | evidence | Prefetch execution artifacts, suspicious binary names, and execution hints |
| `windows/enum-persistence.ps1` | persistence | Run keys, services, tasks, WMI subs, startup folders |
| `windows/enum-artifacts.ps1` | evidence | Common remote-admin, transfer, script, and persistence artifact locations; optional artifact pack support |
| `windows/enum-browser-artifacts.ps1` | evidence | Browser profiles, bookmarks, downloads, typed URLs, and admin-console clues |
| `windows/enum-kerberos-events.ps1` | evidence | Kerberos 4769 activity and weak-encryption ticket indicators |
| `windows/enum-applocker-events.ps1` | evidence | AppLocker allow/block events and LOLBIN execution hints |
| `windows/enum-protections.ps1` | security | AV/EDR status, AppLocker, AMSI, firewall |
| `windows/enum-av-exclusions.ps1` | security | Defender / antimalware / SEP exclusion paths, processes, extensions |
| `windows/enum-usb-history.ps1` | evidence | USB storage, mounted-drive, and removable-volume history |
| `windows/enum-ad.ps1` | domain | Domain info, trusts, SPNs, privileged groups, GPOs |
| `windows/enum-ad-users.ps1` | domain | AD user inventory, ASREP-roastable accounts, service-like users |
| `windows/enum-ad-groups.ps1` | domain | Privileged and operationally relevant domain groups and members |
| `windows/enum-ad-spns.ps1` | domain | SPN-bearing user/computer accounts and Kerberoastable targets |
| `windows/enum-ad-computers.ps1` | domain | Domain computer inventory, OS fields, naming clues, managedBy hints |

### macOS

| Script | Category | What It Collects |
|--------|----------|------------------|
| `macos/enum-system.sh` | system | `sw_vers`, hardware/software profile, users, launchd jobs, FileVault/SIP state |
| `macos/enum-network.sh` | network | Interfaces, routes, DNS, proxies, Wi-Fi prefs, live connections, ARP |
| `macos/enum-persistence.sh` | persistence | LaunchDaemons, LaunchAgents, shell/profile hooks, autologin, cron/at artifacts |
| `macos/enum-credentials.sh` | credentials | Keychain metadata, SSH/GPG material, shell history, cloud tokens, autologin hints |
| `macos/enum-remote-access-artifacts.sh` | pivot | Airport/Wi‑Fi details, VNC/screensharing, Safari last session, SSH remote-access traces |
| `macos/enum-launchd.sh` | persistence | Loaded `launchctl` jobs plus launchd plist labels, programs, watch paths, and logging paths |
| `macos/enum-unified-logs.sh` | logs | Recent `log show` output for launchd, auth, exec/spawn, and network activity |
| `macos/enum-browser-artifacts.sh` | browser | Safari, Chrome, and Firefox artifact locations and recent session/history metadata |

## Execution Methods

### Method 1: Inline (true LOTL — nothing touches disk)

```
remote_exec(session="target", command="<paste script body>")
```

Best for short sequences. The skill can inline any playbook directly.

### Method 2: Upload + Execute + Clean

```
remote_upload(content=<script>, remote_path="/dev/shm/.t", executable=true)
remote_exec(session="target", command="/dev/shm/.t; rm -f /dev/shm/.t")
```

Best for longer scripts. Uses `/dev/shm` (tmpfs, never hits disk on Linux).

### Method 3: Pipe (no file created)

```
remote_exec(session="target", command="sh -c '$(cat <<\"GATHER\"\n<script body>\nGATHER\n)'")
```

Alternative for environments where even tmpfs writes are monitored.

## Output Format

All scripts should produce delimited sections:

```
=== SECTION NAME ===
<data>

=== NEXT SECTION ===
<data>
```

This makes it trivial to parse specific sections from output. Shell variants may also echo the command being run; PowerShell variants may emit equivalent section markers via `Write-Output`.

## Post-Gather Workflow

1. Run appropriate gather script(s)
2. Review output for credentials, pivot paths, persistence
3. Feed discoveries into intel store:
   - `intel_add(category="credential", ...)` for recovered keys/hashes/tokens
   - `intel_add(category="host", ...)` for discovered network neighbors
   - `intel_add(category="account", ...)` for compromised accounts
   - `intel_add(category="pivot", ...)` for reachable internal hosts
4. Plan next action (follow credential trail, eradicate persistence, etc.)

## Triage Quick-Run

For full initial triage of a Linux host:

```bash
# Run all gather scripts in sequence (inline method)
for script in hashdump ssh-keys enum-credentials enum-network enum-system enum-persistence enum-protections; do
  remote_upload(content=<linux/$script.sh>, remote_path="/dev/shm/.g", executable=true)
  remote_exec(session="target", command="/dev/shm/.g; rm -f /dev/shm/.g")
done
```

## macOS notes

The macOS playbooks were scaffolded from the same investigative themes covered by public OS X gather modules such as system enumeration, keychain discovery, wireless preference review, autologin checks, and hash-related account review. In this harness, they are kept read-only and native-command-only.

Focus areas:
- `system_profiler`, `sw_vers`, `launchctl`, `dscl`
- `security list-keychains` and metadata-only keychain review
- Wi‑Fi preference review via `com.apple.airport.preferences`
- autologin discovery via `com.apple.loginwindow`
- FileVault / SIP state for impact and containment planning
- unified log review via `log show`
- browser artifact review for Safari, Chrome, and Firefox

## Validation Checklist

- [ ] Script uses only native OS commands or built-in administrative tooling already present on target hosts
- [ ] Script is read-only (no system modifications)
- [ ] Output uses `=== SECTION ===` delimiters
- [ ] Script handles missing commands gracefully (no errors if tool absent)
- [ ] Script works on minimal installs as gracefully as possible
- [ ] Credentials found are immediately recorded via intel_add
- [ ] Uploaded scripts are cleaned up after execution

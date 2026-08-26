# Playbook Inventory

101 native-OS scripts across all core skill categories. Scripts use commands already present on the target OS; run inline when possible or temporarily stage script text with cleanup. No third-party binaries land on targets.

---

## Gather playbooks

Broad collection scripts. Run these to understand a host's state, recover credentials, map the network, and identify persistence. The agent selects the right ones for the platform automatically.

### Linux — 19 scripts

| Script | Category | What it collects |
|--------|----------|-----------------|
| `first-look.sh` | situational | Live sessions, outbound connections, staging areas (`/tmp`, `/dev/shm`), immediate persistence indicators |
| `hashdump.sh` | credentials | `/etc/shadow`, `/etc/passwd`, `opasswd` |
| `ssh-keys.sh` | credentials | SSH private keys, `authorized_keys`, `known_hosts` across all users |
| `enum-credentials.sh` | credentials | AWS keys, Docker credentials, `.env` files, shell history tokens |
| `enum-cloud-credentials.sh` | credentials | EC2/Azure/GCP IMDS endpoints, IAM role tokens, expiry, blast radius notes |
| `enum-user-history.sh` | evidence | Shell history patterns, suspicious execution, SSH config references |
| `collect-evidence.sh` | evidence | Volatile state snapshot — sessions, connections, processes, disk state, auth logs |
| `ansible-triage.sh` | pivot | Ansible inventory targets, private key references, SSH host hints |
| `enum-vpn-creds.sh` | pivot | OpenVPN, WireGuard, NetworkManager VPN profiles — endpoints and auth references |
| `enum-cifs-creds.sh` | pivot | SMB/CIFS mounts, credential files, target shares |
| `enum-reachability.sh` | pivot | TCP reachability probe via `/dev/tcp` across a target range; tabular OPEN output |
| `enum-network.sh` | network | Interfaces, routes, iptables rules, live connections, DNS, ARP |
| `enum-persistence.sh` | persistence | Crons, systemd units, rc.local, shell profiles, timers |
| `enum-system.sh` | system | Users, packages, services, SUID binaries, kernel |
| `enum-configs.sh` | system | Service configs (Apache, MySQL, sshd, Samba, etc.) |
| `enum-containers.sh` | system | Docker/Podman containers, images, volumes, networks |
| `enum-protections.sh` | security | EDR/AV/IDS detection, kernel hardening state |
| `privesc-check.sh` | privesc | `sudo -l`, SUID, capabilities, writable privileged paths |
| `triage.sh` | meta | One-shot runner combining all core gather categories |

### Windows — 28 scripts

| Script | Category | What it collects |
|--------|----------|-----------------|
| `first-look.ps1` | situational | Live sessions, connections, suspicious tasks/services, Defender state |
| `hashdump.ps1` | credentials | SAM/SYSTEM hive export |
| `lsass-dump.ps1` | credentials | PPL/Credential Guard pre-flight, `comsvcs.dll MiniDump` (LOLBAS), verify + cleanup reminder |
| `enum-credentials.ps1` | credentials | Credential Manager, vault, WiFi profiles, cached logons |
| `enum-unattend-autologon.ps1` | credentials | Unattend/sysprep files, autologon registry values, plaintext credential hints |
| `psreadline-history.ps1` | credentials | PowerShell command history across all user profiles, suspicious command hits |
| `collect-evidence.ps1` | evidence | Volatile state capture — sessions, processes, connections, event log snapshots |
| `enum-prefetch.ps1` | evidence | Prefetch execution artifacts, suspicious binary names |
| `enum-artifacts.ps1` | evidence | Remote-admin, transfer, script, and persistence artifact locations |
| `enum-browser-artifacts.ps1` | evidence | Browser profiles, bookmarks, downloads, typed URLs, admin-console clues |
| `enum-kerberos-events.ps1` | evidence | Kerberos 4769 activity, weak-encryption ticket indicators |
| `enum-applocker-events.ps1` | evidence | AppLocker allow/block events, LOLBIN execution hints |
| `enum-usb-history.ps1` | evidence | USB storage, mounted-drive, and removable-volume history |
| `putty-sessions.ps1` | pivot | PuTTY saved sessions, stored SSH host keys, key-file paths, Pageant presence |
| `enum-reachability.ps1` | pivot | TCP reachability probe via `Test-NetConnection` across a target range; tabular OPEN output |
| `enum-network.ps1` | network | Interfaces, routes, firewall rules, live connections, DNS, shares |
| `enum-dnscache.ps1` | network | DNS client cache entries, suspicious destination hints |
| `enum-rasvpn-events.ps1` | network | RAS/VPN client and server connection and authentication events |
| `enum-persistence.ps1` | persistence | Run keys, services, tasks, WMI subscriptions, startup folders |
| `enum-system.ps1` | system | Users, groups, services, scheduled tasks, installed software |
| `enum-protections.ps1` | security | AV/EDR status, AppLocker, AMSI, firewall state |
| `enum-av-exclusions.ps1` | security | Defender/antimalware/SEP exclusion paths, processes, extensions |
| `enum-ad.ps1` | domain | Domain info, trusts, SPNs, privileged groups, GPOs |
| `enum-ad-users.ps1` | domain | AD user inventory, AS-REP roastable accounts, service-like users |
| `enum-ad-groups.ps1` | domain | Privileged and operationally relevant domain groups and members |
| `enum-ad-spns.ps1` | domain | SPN-bearing user/computer accounts, Kerberoastable targets |
| `enum-ad-computers.ps1` | domain | Domain computer inventory, OS fields, naming clues, managedBy hints |
| `enum-cloud-credentials.ps1` | credentials | EC2/Azure/GCP IMDS endpoints, attached IAM roles/managed identities, expiry, blast radius notes |

### macOS — 11 scripts

| Script | Category | What it collects |
|--------|----------|-----------------|
| `first-look.sh` | situational | Live sessions, outbound connections, launchd persistence indicators, security state |
| `collect-evidence.sh` | evidence | Volatile state snapshot — sessions, connections, processes, launchd jobs, auth log |
| `enum-system.sh` | system | `sw_vers`, hardware/software profile, users, launchd jobs, FileVault/SIP state |
| `enum-network.sh` | network | Interfaces, routes, DNS, proxies, Wi-Fi preferences, live connections, ARP |
| `enum-persistence.sh` | persistence | LaunchDaemons, LaunchAgents, shell/profile hooks, autologin, cron artifacts |
| `enum-credentials.sh` | credentials | Keychain metadata, SSH/GPG material, shell history, cloud tokens, autologin hints |
| `ssh-keys.sh` | credentials | SSH private keys, authorized_keys, known_hosts, per-key fingerprints across `/Users` |
| `enum-remote-access-artifacts.sh` | pivot | Wi-Fi details, VNC/screensharing, Safari last session, SSH remote-access traces |
| `enum-launchd.sh` | persistence | Loaded `launchctl` jobs, plist labels, programs, watch paths, logging paths |
| `enum-unified-logs.sh` | logs | `log show` output for launchd, auth, exec/spawn, and network activity |
| `enum-browser-artifacts.sh` | evidence | Safari, Chrome, Firefox artifact locations, recent session/history metadata |

### Network devices — 3 reference scripts

CLI command references (paste-and-run, not automated). Record findings with `intel_add` manually.

| Script | Device | What it covers |
|--------|--------|---------------|
| `cisco-ios.sh` | Cisco IOS/IOS-XE | Sessions, routing, AAA, VPN, logging, software integrity |
| `cisco-nxos.sh` | Cisco NX-OS | VLANs, CDP/LLDP, accounting log, NTP |
| `juniper-junos.sh` | Juniper JunOS | Security policies, IKE/IPsec, interactive-commands log |

---

## Host IR playbooks

Focused compromise investigation. Use these when you need to prove or disprove attacker presence on a specific host — distinct from broad collection.

| Platform | Script | Purpose |
|----------|--------|---------|
| Linux | `initial-assessment.sh` | Attacker-TTP reconstruction: live activity, persistence clues, pivot artifacts, credential exposure |
| Linux | `integrity-check.sh` | Binary integrity: rpm/dpkg anomalies, LD_PRELOAD hijacks, unexpected setuid binaries |
| macOS | `initial-assessment.sh` | Attacker-perspective investigation: non-Apple persistence, suspicious processes, unified log analysis |
| macOS | `live-response.sh` | Live-response evidence collection: broad volatile capture before containment |
| Windows | `initial-assessment.ps1` | Artifact-first host IR: live state, persistence indicators, security events |
| Windows | `persistence-hunt.ps1` | Deep persistence: Run keys, services, tasks, WMI subscriptions, startup folders, remote-access clues |
| Windows | `eventlog-hunt.ps1` | High-signal event review: logons, PowerShell, services, RDP, Defender, WMI, Sysmon |
| Windows | `eventlog-hunt-lite.ps1` | Fast event sweep (no Sysmon required): logons, PowerShell, service/task creation |
| Windows | `sysmon-hunt.ps1` | Sysmon-focused: process exec, network, registry/file changes, injection, DNS, WMI, pipes |
| Windows | `powershell-reconstruction.ps1` | Reconstruct attacker PowerShell activity from 4103/4104 logs and PSReadLine |
| Windows | `triage.ps1` | Combined first-pass wrapper: host context + event review + Sysmon triage |
| Windows | `integrity-check.ps1` | Binary integrity: Authenticode verification, file-hash anomalies |

---

## Containment playbooks

Evidence-first. Every script captures volatile state, performs the minimum action, verifies success, and emits an `intel_update` snippet.

**Run `collect-evidence` before any containment script.**

| Platform | Script | What it does |
|----------|--------|-------------|
| Linux | `kill-process.sh` | Capture process metadata and hash, SIGTERM → SIGKILL, verify gone |
| Linux | `block-c2.sh` | Record C2 IP, add iptables/nft drop rules inbound and outbound, verify |
| Linux | `disable-account.sh` | Lock password, set shell to nologin, kill sessions, verify |
| Linux | `isolate-host.sh` | Allow-analyst-only iptables, drop all other I/O — nuclear option |
| macOS | `isolate-host.sh` | Allow-analyst-only pf ruleset, block all other I/O — does NOT persist across reboots |
| Windows | `kill-process.ps1` | Stop-Process with pre/post evidence, hash binary |
| Windows | `block-c2.ps1` | New-NetFirewallRule inbound + outbound, verify |
| Windows | `disable-account.ps1` | Local and AD variants, logoff sessions, Stop-Process by owner, verify |
| Windows | `isolate-host.ps1` | Allow-analyst-only Windows Firewall rules, default-block all profiles, verify — ⚠️ persists across reboots |
| macOS | `kill-process.sh` | Pre-kill evidence via lsof, SIGTERM → SIGKILL, verify, check for respawn |
| macOS | `block-c2.sh` | pf rule for C2 IP (inbound + outbound), verify |
| macOS | `disable-account.sh` | dscl password disable, shell to /usr/bin/false, pkill -U, verify |

---

## Eradication playbooks

Evidence-backed removal. Each script: export artifact evidence → remove → verify removal → emit `intel_timeline` snippet.

| Platform | Script | What it removes |
|----------|--------|----------------|
| Linux | `remove-cron.sh` | User or system crontab entries |
| Linux | `remove-systemd-unit.sh` | Systemd service or timer units |
| Linux | `remove-ssh-key.sh` | Attacker key from `authorized_keys` |
| Linux | `remove-profile-hook.sh` | Shell profile hooks (`.bashrc`, `.profile`, `/etc/profile.d/`) |
| Windows | `remove-scheduled-task.ps1` | Scheduled tasks — export XML evidence first |
| Windows | `remove-service.ps1` | Services — export config evidence first |
| Windows | `remove-registry-run.ps1` | Run/RunOnce registry persistence keys |
| Windows | `remove-wmi-subscription.ps1` | WMI EventFilter + Consumer + Binding |
| macOS | `remove-launch-item.sh` | LaunchDaemon or LaunchAgent plist — bootout then move plist to evidence |
| macOS | `remove-cron.sh` | User crontab entries and /etc/cron.d files |
| macOS | `remove-profile-hook.sh` | Shell profile/rc hooks (.zshrc, .zprofile, .zlogin, /etc/profile.d/) |
| macOS | `remove-ssh-key.sh` | Attacker SSH public key from authorized_keys |
| macOS | `remove-btm-login-item.sh` | BTM/login items (macOS 13+ pluginkit + legacy osascript) |

---

## Privilege escalation assessment

Audit scripts for understanding how the attacker escalated (or where they could). Read-only.

| Platform | Script | What it checks |
|----------|--------|---------------|
| Linux | `local-privesc-audit.sh` | `sudo -l`, SUID/SGID, capabilities, writable privileged paths, cron hijacks, GTFOBins candidates |
| Windows | `local-privesc-audit.ps1` | Token privileges, service binary permissions, AlwaysInstallElevated, unquoted service paths, LOLBAS candidates |
| macOS | `local-privesc-audit.sh` | `sudo -l`, SUID, launchd service hijacks, writable privileged paths |

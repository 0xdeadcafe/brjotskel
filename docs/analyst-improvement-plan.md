# Analyst Improvement Plan — LOTL Holy Grail for No-EDR Environments

## The Problem

Your analysts face environments where:
- No EDR visibility — you're blind until you land on a box
- Attacker may already be on the system — you can't trust local tools blindly
- You need to take back control using only what's already there
- You need to pivot through the environment following the attacker's path
- Every action must be justified, logged, and reversible

## What You Already Have (Strengths)

| Area | Status |
|------|--------|
| Remote session management | ✅ Excellent — multi-session, persistent state, audit logged |
| Intel tracking | ✅ Solid — hosts/creds/accounts/pivots with timeline |
| Linux gather playbooks | ✅ Comprehensive (15 scripts) |
| Windows gather playbooks | ✅ Very strong (24 scripts + AD) |
| macOS gather playbooks | ✅ Good (8 scripts) |
| Windows host-IR | ✅ Deep (7 scripts including Sysmon/EventLog/PS reconstruction) |
| Privilege escalation | ✅ Present (LOLBAS/GTFOBins aware) |
| Shell command reference | ✅ Rich corpus (15 reference docs) |
| Network scanning | ✅ Solid nmap playbooks |
| Pivoting infrastructure | ✅ SSH tunnels, SOCKS, ProxyJump |

## What's Missing — The Gaps That Hurt Analysts

---

### 🔴 GAP 1: No "Situational Awareness on Landing" Quick-Start

**Problem:** When an analyst connects to a system for the first time, they need a 30-second situational awareness dump — not a full triage. The current `triage.sh` runs everything. There's no fast "am I alone, what's running, who's logged in, is anything talking outbound right now" script.

**Solution:** Add a `first-look` micro-playbook per platform:

```
gather-playbooks/linux/first-look.sh      # 10 commands, 5 seconds
gather-playbooks/windows/first-look.ps1   # 10 commands, 5 seconds  
gather-playbooks/macos/first-look.sh      # 10 commands, 5 seconds
```

Contents (Linux example):
- `w` — who's logged in right now
- `ps auxf --sort=-%cpu | head -30` — top processes by CPU
- `ss -tunap | grep ESTABLISHED` — active connections
- `last -10` — recent logins
- `cat /etc/hostname; uname -r; uptime`
- `ls -la /tmp /dev/shm /var/tmp 2>/dev/null | grep -v "^total"` — attacker staging areas
- `find / -mmin -60 -type f 2>/dev/null | grep -v '/proc\|/sys'` — files modified in last hour
- `crontab -l 2>/dev/null; ls /etc/cron.d/` — immediate scheduled threats
- `iptables -L -n 2>/dev/null | head -20` — firewall state
- `systemctl list-units --type=service --state=running | wc -l` — service count baseline

---

### 🔴 GAP 2: No Containment Playbooks (Only Reference Docs)

**Problem:** `reference/active-containment.md` exists as a command reference, but there's no structured **containment skill** with ready-to-run scripts. When an analyst finds the attacker's C2 process or persistence, they need one-click containment scripts, not reference reading.

**Solution:** New skill: `.pi/skills/containment-playbooks/`

```
containment-playbooks/
  SKILL.md
  linux/
    kill-process.sh          # Kill by PID/name, verify gone
    block-outbound-ip.sh     # iptables/nftables C2 block
    disable-user.sh          # Lock account, expire sessions
    revoke-ssh-keys.sh       # Remove authorized_keys entries
    isolate-network.sh       # Drop all except analyst's SSH
    disable-cron-job.sh      # Comment out / disable specific cron
    disable-systemd-unit.sh  # Stop + mask unit
  windows/
    kill-process.ps1         # Stop-Process with verification
    block-outbound-ip.ps1    # Windows Firewall rule
    disable-user.ps1         # Disable-ADAccount or net user /active:no
    revoke-sessions.ps1      # Logoff sessions, invalidate tokens
    disable-task.ps1         # Disable-ScheduledTask
    disable-service.ps1      # Stop + set StartType Disabled
    isolate-network.ps1      # Firewall deny-all + allow analyst
  macos/
    kill-process.sh
    block-outbound-ip.sh     # pfctl rules
    disable-user.sh
    disable-launchd.sh       # launchctl bootout + overrides
```

Each script follows the pattern:
1. **Verify target** (show what will be affected)
2. **Preserve evidence** (capture state before change)
3. **Execute containment** (the actual action)
4. **Verify success** (confirm it worked)
5. **Document** (output structured for `intel_timeline`)

---

### 🔴 GAP 3: No Eradication Playbooks

**Problem:** After containment, analysts need to **remove** persistence, clean artifacts, and verify removal. The `active-containment.md` reference covers this conceptually, but there's no structured eradication workflow.

**Solution:** New skill: `.pi/skills/eradication-playbooks/`

```
eradication-playbooks/
  SKILL.md
  linux/
    remove-cron-persistence.sh
    remove-systemd-persistence.sh
    remove-ssh-key-persistence.sh
    remove-shell-profile-hooks.sh
    remove-webshell.sh
    verify-clean.sh              # Post-eradication validation
  windows/
    remove-registry-persistence.ps1   # Run keys, services
    remove-scheduled-task.ps1
    remove-wmi-persistence.ps1
    remove-startup-persistence.ps1
    remove-service-persistence.ps1
    verify-clean.ps1                  # Post-eradication validation
  macos/
    remove-launchd-persistence.sh
    remove-login-item.sh
    verify-clean.sh
```

Pattern: **evidence-first removal with verification**.

---

### 🟠 GAP 4: No "Credential Trail" Workflow Automation

**Problem:** The core workflow is: land on host → find creds → validate creds → pivot → repeat. Currently this is entirely manual. The analyst has to remember to try each credential against each discovered host.

**Solution:** Add a `credential-spray` helper skill or extension tool:

```
# New tool: intel_validate_cred
# Takes a credential ID and a list of hosts, attempts validation via native means
# Uses: ssh (password test), netexec smb (NTLM), netexec winrm, etc.
# Records results back to intel store automatically
```

Implementation sketch (runs from harness, not on target):
```bash
# For password creds:
netexec smb <host> -u <user> -p <pass> --no-bruteforce
netexec winrm <host> -u <user> -p <pass>
# For NTLM:
netexec smb <host> -u <user> -H <hash>
# For SSH keys:
ssh -o BatchMode=yes -i <key> <user>@<host> exit
```

Auto-records `valid_on` results back into the credential entry.

---

### 🟠 GAP 5: No Network Baseline / Anomaly Detection Guidance

**Problem:** Without EDR, the analyst needs to figure out what's *normal* vs *abnormal* on a system using only native commands. There's no "expected vs suspicious" cheat sheet embedded in the playbooks.

**Solution:** Add annotated suspicious-indicator sections to `first-look` and gather scripts. Create a reference doc:

```
shell-commands/reference/suspicious-indicators.md
```

Contents:
- Suspicious process names/paths by platform
- Suspicious outbound ports (4444, 8080 to non-web, 53 to non-DNS server, ICMP data)
- Suspicious service/cron patterns
- Suspicious file locations (/dev/shm, /tmp/.*, C:\Users\Public, C:\ProgramData unusual dirs)
- Suspicious user account patterns ($ suffix, UID 0 non-root, recently created)
- Suspicious scheduled task patterns (base64, encoded, downloads)
- Common attacker tooling filenames/hashes (mimikatz, nc variants, chisel, ligolo, etc.)

---

### 🟠 GAP 6: No Multi-Host Correlation View

**Problem:** When investigating 5+ hosts, the analyst needs to see the big picture: which hosts share credentials, which have active attacker sessions, what the pivot graph looks like. The current `intel_summary` is just counts.

**Solution:** Add an `intel_map` tool or enhanced `/intel` command:

```
intel_map() output:

=== Attack Graph ===
adminws [compromised/pivot] 
  → web01 [compromised/c2] via deploy-ssh-key (ssh)
    → db01 [suspected] via deploy-ssh-key (ssh-proxy-jump)
  → dc01 [suspected] via admin-ntlm (winrm)

=== Shared Credentials ===
deploy-ssh-key: valid on web01, db01, app01
admin-ntlm: valid on dc01, fileserver

=== Active Sessions ===
web01: SSH ✓ (34 commands, 12min)
dc01: WinRM ✓ (8 commands, 5min)

=== Unvalidated Leads ===
- Credential corp\backup found on web01, not tested on: dc01, sql01
- Host fileserver01 discovered via DNS cache on dc01, not yet accessed
```

---

### 🟠 GAP 7: No "Analyst Runbook" Guided Workflow

**Problem:** A junior analyst lands in the container and doesn't know where to start. The README documents capabilities but doesn't provide a step-by-step "here's what you do when you get handed an incident."

**Solution:** Add `docs/analyst-runbook.md`:

```markdown
# Analyst Runbook

## Phase 1: Initial Access
1. Get authorized scope (IP ranges, hostnames, credentials)
2. Record scope: intel_add(category="host", ...) for each known target
3. Validate connectivity: nmap quick scan
4. Connect to first compromised host: remote_connect(...)

## Phase 2: First Look
5. Run first-look script (30 seconds)
6. Look for: unexpected users, outbound connections, recent files, active processes

## Phase 3: Deep Triage
7. Run full triage or targeted gather scripts
8. Record every credential found immediately
9. Record every new host/pivot discovered

## Phase 4: Credential Trail
10. For each credential found, validate against other hosts
11. Connect to newly validated hosts
12. Repeat Phase 2-3 on each new host

## Phase 5: Containment
13. Once attacker scope is mapped, contain:
    - Kill C2 processes
    - Block C2 IPs
    - Disable compromised accounts
14. Verify containment held

## Phase 6: Eradication  
15. Remove all persistence (use eradication playbooks)
16. Force credential rotation
17. Verify with post-eradication checks

## Phase 7: Documentation
18. Review timeline: intel_timeline(action="view", count=100)
19. Export intel for incident report
```

---

### 🟡 GAP 8: No Log Collection/Export for Hosts Without Central Logging

**Problem:** Without EDR or central logging, evidence lives only on the host. If the analyst doesn't grab it now, it's gone. There's no structured "evidence bag" workflow.

**Solution:** Add `gather-playbooks/linux/collect-evidence.sh` and Windows equivalent:

```bash
# Collects and tarballs key evidence files for offline analysis
# Outputs to /dev/shm or a specified path
# Includes: auth logs, shell histories, cron/systemd configs, 
#           /tmp and /dev/shm contents, recent modified files,
#           network state snapshot, process tree snapshot
```

Plus an extension tool: `remote_collect` that pulls evidence back to the harness:
```
remote_exec → tar/zip evidence on target
remote_exec → base64 encode (for small files)
local bash → decode and store in workspace/evidence/<host>/
```

---

### 🟡 GAP 9: No Integrity Verification (Rootkit/Tampered Binary Detection)

**Problem:** On hosts without EDR, you can't trust `ps`, `ss`, `netstat`, etc. The attacker may have replaced them. There's no native integrity check workflow.

**Solution:** Add `gather-playbooks/linux/integrity-check.sh`:

```bash
# Compares installed binaries against package manager signatures
# RPM: rpm -Va
# DEB: dpkg --verify / debsums
# Check for LD_PRELOAD hooks
# Check for modified /etc/ld.so.preload
# Check for kernel module persistence (lsmod vs expected)
# Verify critical binaries: stat + file + md5sum on ps, ss, netstat, ls, find
# Check /proc/*/maps for injected libraries
```

Windows equivalent: `gather-playbooks/windows/integrity-check.ps1`
```powershell
# sfc /verifyonly
# Check for unsigned services/drivers
# Check for DLL search order hijacking in system paths
# Verify critical system binaries with Get-AuthenticodeSignature
```

---

### 🟡 GAP 10: No "What Can They See From Here" Network Recon Script

**Problem:** When you land on a host, you need to understand what the attacker can reach from there — not just what's connected now, but what's *reachable*. This is different from `enum-network.sh` which shows current state.

**Solution:** Add `gather-playbooks/linux/reachability-probe.sh`:

```bash
# From current host, probe common internal services
# Uses only native tools: bash /dev/tcp, ping, nc (if available)
# Tests: SSH(22), SMB(445), WinRM(5985), RDP(3389), HTTP(80,443,8080)
# Against: discovered hosts from ARP, routes, DNS, /etc/hosts
# Output: reachability matrix for pivot planning
```

---

### 🟡 GAP 11: No Operator Cheat Sheet / Quick Reference in the Container

**Problem:** Analysts forget the exact tool syntax. The README is long. They need a quick-reference card.

**Solution:** Add `bin/help` or a `/help` slash command:

```
/help                    → Show workflow phases
/help connect            → remote_connect examples  
/help creds              → intel credential workflow
/help pivot              → tunneling/proxying quick ref
/help contain            → containment command quick ref
/help lotl linux         → top 10 LOTL commands for linux triage
/help lotl windows       → top 10 LOTL commands for windows triage
```

---

### 🟡 GAP 12: Missing Harness-Side Credential Tools

**Problem:** The harness has Impacket and NetExec but no structured skill for *using them*. When an analyst recovers an NTLM hash, they need to know: "now what?" 

**Solution:** Add skill or reference doc: `shell-commands/reference/harness-tools.md`

```markdown
## From the Harness (not on target)

### Validate NTLM hash
netexec smb <target> -u <user> -H <hash>
netexec winrm <target> -u <user> -H <hash>

### Get a shell with hash
psexec.py -hashes :<hash> <domain>/<user>@<target>
wmiexec.py -hashes :<hash> <domain>/<user>@<target>
smbexec.py -hashes :<hash> <domain>/<user>@<target>

### Dump more creds from remote host
secretsdump.py -hashes :<hash> <domain>/<user>@<target>

### Through SOCKS pivot
proxychains netexec smb 10.10.10.0/24 -u <user> -H <hash>
proxychains secretsdump.py ...

### Kerberos attacks
getTGT.py <domain>/<user> -hashes :<hash>
getST.py -spn <spn> -hashes :<hash> <domain>/<user>
export KRB5CCNAME=<ticket.ccache>
psexec.py -k -no-pass <domain>/<user>@<target>
```

---

## Priority Implementation Order

| # | Item | Effort | Impact |
|---|------|--------|--------|
| 1 | `first-look` micro-playbooks (3 files) | 2h | 🔴 Immediate analyst velocity |
| 2 | `docs/analyst-runbook.md` | 2h | 🔴 Junior analyst enablement |
| 3 | Containment playbooks skill | 4h | 🔴 Take-back-control capability |
| 4 | `suspicious-indicators.md` reference | 2h | 🟠 "What's abnormal" guidance |
| 5 | Eradication playbooks skill | 4h | 🟠 Complete the IR lifecycle |
| 6 | `intel_map` / attack graph tool | 3h | 🟠 Multi-host situational awareness |
| 7 | Credential validation helper | 3h | 🟠 Automate the pivot workflow |
| 8 | `harness-tools.md` reference | 1h | 🟠 Impacket/NetExec quick-ref |
| 9 | `/help` quick reference command | 2h | 🟡 Reduce friction |
| 10 | Evidence collection scripts | 3h | 🟡 Preserve before containment |
| 11 | Integrity check scripts | 2h | 🟡 Detect tampered binaries |
| 12 | Reachability probe scripts | 2h | 🟡 Map pivot options |

---

## Summary

Your framework is already **strong on collection and investigation**. The biggest gaps are:

1. **Speed to action** — analysts need 30-second situational awareness, not 5-minute full triage as the first move
2. **Taking back control** — no structured containment/eradication scripts (only reference docs)
3. **Guided workflow** — no step-by-step runbook for analysts under pressure
4. **Credential chain automation** — the find→validate→pivot loop is entirely manual
5. **"What's suspicious?" guidance** — without EDR context, analysts need built-in anomaly awareness

Fix items 1-3 and your analysts can respond to an incident end-to-end without leaving the harness. Items 4-8 make them fast. Items 9-12 make them thorough.

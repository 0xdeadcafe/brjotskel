# Analyst Runbook

Flexible workflow reference for experienced IR analysts. Not a step-by-step checklist — a map of capabilities and decision points.

## Phases

```
LAND → ASSESS → PURSUE → CONTAIN → ERADICATE → VERIFY
```

Phases overlap. You may contain one host while still pursuing on another.

---

## Land

Establish access to the first confirmed compromised host.

```text
remote_connect(protocol="ssh", target="root@10.10.10.5", name="web01", password="...")
```

If SSH isn't available:
```text
remote_connect(protocol="winrm", target="administrator@10.10.10.20", name="dc01", password="...")
```

If the target isn't directly reachable:
```text
remote_tunnel(type="local", via="root@jumpbox", local_port=2222, remote_host="target", remote_port=22)
remote_connect(protocol="ssh", target="root@localhost", port=2222, name="target01")
```

Record immediately:
```text
intel_add(category="host", id="web01", data="...", summary="Initial compromised host")
```

---

## Assess

**First-look (30 seconds):**
```text
remote_exec(session="web01", command="<linux/first-look.sh>")
```

**Decision tree after first-look:**

| Finding | Action |
|---------|--------|
| Active attacker session/process | Decide: observe or contain immediately |
| Outbound C2 connection | Note IP/port, decide containment timing |
| Staging files in /tmp, /dev/shm | Hash + collect before removal |
| Persistence mechanisms | Full persistence hunt before eradication |
| Nothing obvious | Deeper triage — gather scripts |

**Go deeper when needed:**
- Credentials: `linux/hashdump.sh`, `linux/ssh-keys.sh`, `windows/enum-credentials.ps1`
- Persistence: `linux/enum-persistence.sh`, `windows/persistence-hunt.ps1`
- Network context: `linux/enum-network.sh`, `windows/enum-network.ps1`
- Event history: `windows/eventlog-hunt.ps1`, `windows/sysmon-hunt.ps1`
- AD scope: `windows/enum-ad.ps1`, `windows/enum-ad-users.ps1`

---

## Pursue

Follow the credential trail. Every credential found → validate → pivot.

### Credential recovery
```text
remote_exec(session="web01", command="cat /etc/shadow")
remote_exec(session="dc01", command="reg save HKLM\\SAM C:\\temp\\sam.hiv")
```

Record every find:
```text
intel_add(category="credential", id="admin-hash", data="type: ntlm-hash\nusername: admin\nsecret: aad3b...\nvalid_on:\n  - dc01\nsource:\n  host: web01\n  method: secretsdump", summary="Admin NTLM from web01")
```

### Validation from harness
```bash
# NTLM hash
netexec smb 10.10.10.20 -u admin -H aad3b...
netexec winrm 10.10.10.20 -u admin -H aad3b...

# Password
netexec smb 10.10.10.0/24 -u svc_sql -p 'Password1' --no-bruteforce

# SSH key
ssh -o BatchMode=yes -i workspace/intel/keys/deploy-ed25519 deploy@10.10.20.10 exit
```

### Pivot when direct access is blocked

**SSH tunnel (preferred):**
```text
remote_tunnel(type="dynamic", via="root@web01", local_port=1080, description="SOCKS via web01")
# Then: proxychains netexec smb 10.10.20.0/24 -u admin -H hash
```

**Relay when SSH isn't available on the pivot:**
```text
remote_relay(session="dc01", target_host="10.10.30.10", target_port=445, listen_port=44450)
# Then: netexec smb 10.10.10.20 --port 44450 -u sa -H hash
```

**Chain for deep networks:**
```text
# Harness → web01 (SSH) → dc01 (WinRM) → sql01 (SMB only)
remote_tunnel(type="local", via="root@web01", local_port=5985, remote_host="dc01", remote_port=5985)
remote_connect(protocol="winrm", target="administrator@localhost", port=5985, name="dc01")
remote_relay(session="dc01", target_host="sql01", target_port=445, listen_port=44450)
remote_tunnel(type="local", via="root@web01", local_port=44450, remote_host="dc01", remote_port=44450)
```

### Track the graph
```text
intel_add(category="pivot", id="to-sql01", data="target: sql01\nchain:\n  - hop: dc01\n    method: netsh-portproxy\nstatus: confirmed")
intel_query(query_type="all_pivots")
intel_summary()
```

---

## Contain

**Timing decision:** Contain when you've mapped enough of the attacker's footprint that they can't simply move to an unmapped host. Premature containment tips them off; late containment lets them dig deeper.

### Process kill
```bash
# Linux
kill -9 <pid>; ps aux | grep <name>

# Windows
Stop-Process -Id <pid> -Force; Get-Process -Id <pid> -ErrorAction SilentlyContinue
```

### Block C2 IP
```bash
# Linux
iptables -I OUTPUT -d <c2_ip> -j DROP
iptables -I INPUT -s <c2_ip> -j DROP

# Windows
New-NetFirewallRule -DisplayName "Block C2" -Direction Outbound -RemoteAddress <c2_ip> -Action Block
New-NetFirewallRule -DisplayName "Block C2 In" -Direction Inbound -RemoteAddress <c2_ip> -Action Block
```

### Disable account
```bash
# Linux
usermod -L <user>; passwd -l <user>

# Windows (local)
net user <user> /active:no

# Windows (AD)
Disable-ADAccount -Identity <user>
```

### Network isolation (nuclear option)
```bash
# Linux — allow only analyst SSH, drop everything else
iptables -F
iptables -A INPUT -s <analyst_ip> -p tcp --dport 22 -j ACCEPT
iptables -A OUTPUT -d <analyst_ip> -p tcp --sport 22 -j ACCEPT
iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP

# Windows
New-NetFirewallRule -DisplayName "Allow Analyst" -Direction Inbound -RemoteAddress <analyst_ip> -Action Allow
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block
```

### Record containment
```text
intel_timeline(action="add", entry_type="containment", entry_action="contained", target="web01", summary="Blocked C2 185.x.x.x, killed PID 4523")
```

---

## Eradicate

Remove persistence only **after** documenting it.

### Common persistence removal

```bash
# Linux cron
crontab -r -u <user>  # or edit specific entry
rm /etc/cron.d/<malicious>

# Linux systemd
systemctl stop <unit>; systemctl disable <unit>; systemctl mask <unit>
rm /etc/systemd/system/<unit>; systemctl daemon-reload

# Linux SSH keys
# Edit /root/.ssh/authorized_keys — remove attacker's key

# Windows scheduled task
Disable-ScheduledTask -TaskName "<name>"
Unregister-ScheduledTask -TaskName "<name>" -Confirm:$false

# Windows service
Stop-Service "<name>"; Set-Service "<name>" -StartupType Disabled
sc.exe delete "<name>"

# Windows Run key
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "<name>"

# Windows WMI
Get-WmiObject -Class __FilterToConsumerBinding -Namespace root/subscription | Where-Object { $_.Filter -match "<name>" } | Remove-WmiObject
Get-WmiObject -Class __EventFilter -Namespace root/subscription | Where-Object { $_.Name -match "<name>" } | Remove-WmiObject
Get-WmiObject -Class CommandLineEventConsumer -Namespace root/subscription | Where-Object { $_.Name -match "<name>" } | Remove-WmiObject
```

### Force credential rotation

All credentials recovered during the investigation must be rotated:
```text
intel_query(query_type="all_credentials")
# For each: coordinate rotation with identity team
intel_timeline(action="add", entry_type="credential", entry_action="rotated", target="admin-hash", summary="Password reset forced by identity team")
```

---

## Verify

Post-eradication checks — run first-look again plus targeted validation.

```bash
# Verify persistence is gone
systemctl list-units --type=service --state=running | grep <name>
schtasks /query /tn "<name>" 2>&1

# Verify no C2 reconnection
ss -tunap | grep ESTABLISHED
Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -eq '<c2_ip>' }

# Verify account disabled
id <user> 2>&1  # should fail
net user <user> | findstr "active"

# Verify firewall holds
iptables -L -n | grep <c2_ip>
Get-NetFirewallRule -DisplayName "Block C2" | Get-NetFirewallAddressFilter
```

Record:
```text
intel_timeline(action="add", entry_type="eradication", entry_action="cleared", target="web01", summary="All persistence removed, C2 blocked, credentials rotated, re-triage clean")
```

---

## Tool Quick Reference

| Need | Tool |
|------|------|
| Connect to host | `remote_connect` |
| Run command | `remote_exec` |
| SSH tunnel / SOCKS | `remote_tunnel` |
| Relay through non-SSH pivot | `remote_relay` |
| Record finding | `intel_add` |
| Find creds for a host | `intel_query(query_type="for_host", target="...")` |
| Get password/hash for use | `intel_get_cred(id="...")` |
| See the big picture | `intel_summary` |
| Record action | `intel_timeline(action="add", ...)` |
| List active connections | `remote_sessions` |
| Scan network segment | `nmap -Pn -sT --open -p 22,445,3389,5985 <target>` |
| Validate creds at scale | `netexec smb <range> -u <user> -H <hash>` |
| Dump remote creds | `secretsdump.py -hashes :<hash> <domain>/<user>@<host>` |
| Get shell with hash | `psexec.py -hashes :<hash> <domain>/<user>@<host>` |
| Route through pivot | `proxychains <tool>` (after dynamic SOCKS tunnel) |

---

## Decision Heuristics

**When to go deeper vs. move on:**
- Found credentials → always validate against other hosts before moving on
- Found persistence but no credentials → look harder (attacker needed creds to get there)
- Host is noisy/active → prioritize volatile collection before it changes

**When to contain:**
- You've mapped the credential blast radius
- Attacker is actively exfiltrating
- You're confident they can't pivot somewhere unmapped
- Incident commander says go

**When to relay vs. tunnel:**
- Pivot has SSH → `remote_tunnel`
- Pivot is Windows without SSH → `remote_relay` (netsh portproxy)
- Pivot is Linux without SSH → `remote_relay` (socat/ncat)
- Need to route many tools → dynamic SOCKS tunnel

**When to use the harness vs. native commands on target:**
- Credential validation → from harness (netexec, secretsdump)
- Credential dumping → on target (reg save, cat /etc/shadow)
- Network scanning → from harness through SOCKS
- Process/session kill → on target
- Firewall rules → on target

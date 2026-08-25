# Analyst Runbook

Operational reference for experienced IR analysts. Not a step-by-step checklist — a map of capabilities, commands, and decision points for active incidents.

## Phases

```
LAND → ASSESS → PURSUE → CONTAIN → ERADICATE → VERIFY
```

Phases overlap. You may be containing one host while still pursuing credentials on another. The intel store tracks state across phases so nothing gets lost between sessions.

---

## Starting cold

When you're handed an incident with an IP, a credential, and an incident brief:

```text
# 1. Record what you know
intel_add(category="host", id="web01",
  data="ip: 10.10.10.5\nplatform: linux\nstatus: suspected\nsource:\n  method: incident brief",
  summary="Initial suspected compromised host")

# 2. Verify connectivity (from the harness)
```
```bash
nmap -Pn -sT --open -p 22,80,443,445,3389,5985 10.10.10.5
```
```text
# 3. Connect and get immediate situational awareness
remote_connect(protocol="ssh", target="root@10.10.10.5", name="web01", password="...")
/assess web01
```

---

## Land

### SSH

```text
remote_connect(protocol="ssh", target="root@10.10.10.5", name="web01", password="...")
remote_connect(protocol="ssh", target="deploy@10.10.20.10", name="db01",
  identity="workspace/intel/keys/deploy-key")
```

### WinRM

```text
remote_connect(protocol="winrm", target="administrator@10.10.10.20", name="dc01", password="...")
```

### Target not directly reachable

```text
# SSH tunnel through a pivot
remote_tunnel(type="local", via="root@web01", local_port=2222,
  remote_host="internal", remote_port=22)
remote_connect(protocol="ssh", target="root@localhost", port=2222, name="internal01")

# Native relay when pivot has no SSH server
remote_relay(session="dc01", target_host="10.10.30.10", target_port=22, listen_port=4422)
remote_connect(protocol="ssh", target="user@10.10.10.20", port=4422, name="sql01")
```

See [relay-pivoting.md](relay-pivoting.md) for the full decision tree.

### Record the landing

```text
intel_add(category="host", id="web01",
  data="ip: 10.10.10.5\nplatform: linux\nstatus: compromised\nsource:\n  method: authorized scope / initial landing",
  summary="Initial foothold — confirmed compromised")
```

---

## Assess

Type `/assess <session>` for platform-aware first-look commands. Or run manually:

### First look — 30 seconds

Answers: Am I alone? What's talking outbound right now? Any staging files? Immediate persistence?

```text
# Linux — read the script and run it inline on the session
remote_exec(session="web01", command="<read and paste linux/first-look.sh>")

# Windows
remote_exec(session="dc01", command="<read and paste windows/first-look.ps1>")

# macOS
remote_exec(session="mac01", command="<read and paste macos/first-look.sh>")
```

**Running playbooks:** Ask pi directly (`run linux/first-look.sh on web01`) and it will read the script and paste it inline. For larger scripts, use `remote_upload` to stage them to a temp path, run, then remove.

### After first look

| Finding | Response |
|---------|----------|
| Active attacker session or process | Decide: observe to map more, or contain immediately |
| Outbound C2 connection | Note C2 IP and port; decide containment timing |
| Staging files in `/tmp`, `/dev/shm`, `C:\Users\Public` | Hash and collect before touching |
| Persistence mechanism present | Full persistence hunt before eradication |
| Nothing obvious | Run deeper gather scripts |

### Deeper triage

- **Credentials**: `linux/hashdump.sh`, `linux/ssh-keys.sh`, `windows/enum-credentials.ps1`, `windows/psreadline-history.ps1`, `macos/enum-credentials.sh`
- **Persistence**: `linux/enum-persistence.sh`, `windows/enum-persistence.ps1`, `macos/enum-persistence.sh`
- **Network context**: `linux/enum-network.sh`, `windows/enum-network.ps1`, `macos/enum-network.sh`
- **Event history**: `windows/eventlog-hunt.ps1`, `windows/sysmon-hunt.ps1`
- **AD scope**: `windows/enum-ad.ps1`, `windows/enum-ad-users.ps1`, `windows/enum-ad-spns.ps1`
- **Full triage**: `linux/triage.sh`, `windows/triage.ps1`

---

## Pursue

Follow the credential trail. Every credential found → validate → pivot.

Type `/pursue` for a chase-board view of current intel and next actions.

### Recover credentials

```bash
# Linux — shadow file and SSH keys
remote_exec(session="web01", command="<linux/hashdump.sh>")
remote_exec(session="web01", command="<linux/ssh-keys.sh>")
remote_exec(session="web01", command="<linux/enum-credentials.sh>")

# Windows — registry hives (requires admin)
remote_exec(session="dc01",
  command="reg save HKLM\\SAM C:\\Windows\\Temp\\s.hiv; reg save HKLM\\SYSTEM C:\\Windows\\Temp\\sy.hiv")
# Then: secretsdump.py -sam s.hiv -system sy.hiv LOCAL

# Windows — credential manager and PowerShell history
remote_exec(session="dc01", command="<windows/enum-credentials.ps1>")
remote_exec(session="dc01", command="<windows/psreadline-history.ps1>")

# macOS — keychain metadata and SSH material
remote_exec(session="mac01", command="<macos/enum-credentials.sh>")
```

### Record every find

```text
# Password
intel_add(category="credential", id="svc-sql-pass",
  data="type: password\nusername: svc_sql\ndomain: corp.local\nsecret: Winter2024!\nstatus: active\nvalid_on:\n  - sql01\nsource:\n  host: dc01\n  method: psreadline history\n  playbook: windows/psreadline-history.ps1",
  summary="svc_sql password from PSReadLine history on dc01")

# NTLM hash
intel_add(category="credential", id="admin-ntlm",
  data="type: ntlm-hash\nusername: Administrator\ndomain: corp.local\nsecret: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\nstatus: active\nvalid_on:\n  - dc01\nsource:\n  host: dc01\n  method: secretsdump\n  playbook: windows/hashdump.ps1",
  summary="Domain admin NTLM recovered from dc01")

# SSH key
intel_add(category="credential", id="deploy-key",
  data="type: ssh-key\nusername: deploy\nkey_file: workspace/intel/keys/deploy-ed25519\nstatus: active\nvalid_on:\n  - web01\nsource:\n  host: web01\n  method: user SSH directory\n  path: /home/deploy/.ssh/id_ed25519\n  playbook: linux/ssh-keys.sh",
  summary="deploy SSH key recovered from web01")
```

Use `bin/intel-snippet` to generate these payloads from structured gather output. See [intel-import-workflow.md](intel-import-workflow.md).

### Validate from the harness

```bash
# NTLM hash
netexec smb 10.10.10.0/24 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:31d6... --no-bruteforce
netexec winrm 10.10.10.20 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:31d6...

# Password
netexec smb 10.10.10.0/24 -u svc_sql -p 'Winter2024!' --no-bruteforce

# SSH key
ssh -o BatchMode=yes -i workspace/intel/keys/deploy-ed25519 deploy@10.10.20.10 exit

# Via SOCKS proxy
proxychains netexec smb 10.10.20.0/24 -u admin -H <hash>
```

### Remote credential dump

```bash
# From harness using a recovered hash
secretsdump.py -hashes :31d6... corp.local/Administrator@10.10.10.20

# Via SOCKS
proxychains secretsdump.py -hashes :31d6... corp.local/Administrator@10.10.20.10
```

### Pivot when direct access is blocked

**SSH tunnel (preferred when the pivot has SSH):**

```text
remote_tunnel(type="dynamic", via="root@web01", local_port=1080)
# Then: proxychains netexec smb 10.10.20.0/24 -u admin -H <hash>

remote_tunnel(type="local", via="root@web01", local_port=5985,
  remote_host="dc01", remote_port=5985)
remote_connect(protocol="winrm", target="administrator@localhost", port=5985, name="dc01")
```

**Native relay (pivot has no SSH server):**

```text
remote_relay(session="dc01", target_host="10.10.30.10", target_port=445, listen_port=44450)
# Then: netexec smb 10.10.10.20 --port 44450 -u sa -H <hash>
```

See [relay-pivoting.md](relay-pivoting.md) for the decision tree and multi-hop chaining.

### Track the pivot graph

```text
intel_add(category="pivot", id="to-dc01",
  data="target: dc01\nchain:\n  - hop: web01\n    method: ssh-local-forward\nstatus: active\nsource:\n  method: SSH tunnel via web01",
  summary="Reached dc01 via SSH tunnel through web01")

intel_query(query_type="all_pivots")
intel_summary()
```

### Kerberoasting and AS-REP roasting (AD environments)

When `enum-ad-spns.ps1` or `enum-ad-users.ps1` reveals Kerberoastable SPNs or AS-REP roastable accounts, run the following from the **harness** using a recovered domain credential:

```bash
# Kerberoasting — request TGS tickets for SPN-bearing accounts
# Requires: any valid domain credential
GetUserSPNs.py corp.local/user:password -dc-ip 10.10.10.20 -request -outputfile kerberoast.txt

# Via NTLM hash (pass-the-hash)
GetUserSPNs.py corp.local/user -hashes :NTLM_HASH -dc-ip 10.10.10.20 -request -outputfile kerberoast.txt

# AS-REP roasting — no credential needed, targets accounts with pre-auth disabled
GetNPUsers.py corp.local/ -dc-ip 10.10.10.20 -no-pass -usersfile <(echo 'svc_backup') -format hashcat -outputfile asrep.txt

# Hash files are written to the current directory.
# Transfer them to an external cracking rig via the mounted workspace/ volume:
#   cp kerberoast.txt /opt/brjotskel/workspace/
#   cp asrep.txt      /opt/brjotskel/workspace/
# Then crack on a GPU rig (hashcat is not in the container — CPU cracking is impractical for $krb5tgs$):
#   hashcat -m 13100 kerberoast.txt rockyou.txt   # TGS-REP
#   hashcat -m 18200 asrep.txt rockyou.txt        # AS-REP
# Wordlist: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
```

Record cracked tickets:

```bash
# Generate intel_add payload from a cracked TGS
bin/intel-snippet kerberos-ticket \
  --id svc-sql-tgs \
  --username svc_sql \
  --domain corp.local \
  --ticket-type tgs \
  --spn MSSQLSvc/sql01.corp.local:1433 \
  --cracked-password 'Winter2024!' \
  --source-host dc01

# AS-REP roast result
bin/intel-snippet kerberos-ticket \
  --id svc-backup-asrep \
  --username svc_backup \
  --domain corp.local \
  --ticket-type asrep \
  --cracked-password 'Backup123!' \
  --source-host dc01
```

**Then validate the cracked password immediately** — treat it like any other recovered credential:

```bash
netexec smb 10.10.10.0/24 -u svc_sql -p 'Winter2024!' --no-bruteforce
```

---

## Contain

**Timing:** Contain when you've mapped enough of the footprint that the attacker can't pivot to an unmapped host. Premature containment tips them off; late containment lets them dig deeper.

Type `/contain <session>` for an evidence-first containment command pack.

### Kill the process

```bash
# Linux
kill -9 <pid>
ps aux | grep <name>    # verify gone

# Windows
Stop-Process -Id <pid> -Force
Get-Process -Id <pid> -ErrorAction SilentlyContinue    # should return nothing

# macOS
kill -9 <pid>
pgrep -l <name>    # verify
```

### Block C2 IP

```bash
# Linux
iptables -I OUTPUT -d <c2_ip> -j DROP
iptables -I INPUT  -s <c2_ip> -j DROP
iptables -L -n | grep <c2_ip>    # verify

# Windows
New-NetFirewallRule -DisplayName "Block C2 Out" -Direction Outbound -RemoteAddress <c2_ip> -Action Block
New-NetFirewallRule -DisplayName "Block C2 In"  -Direction Inbound  -RemoteAddress <c2_ip> -Action Block

# macOS
echo "block drop from any to <c2_ip>\nblock drop from <c2_ip> to any" | pfctl -f -
pfctl -sr | grep <c2_ip>    # verify
```

### Disable account

```bash
# Linux
usermod -L <user>; passwd -l <user>

# Windows (local)
net user <user> /active:no

# Windows (AD)
Disable-ADAccount -Identity <user>

# macOS
dscl . -passwd /Users/<user> '*'
```

### Network isolation — nuclear option

```bash
# Linux — allow only analyst SSH, drop everything else
iptables -F
iptables -A INPUT  -s <analyst_ip> -p tcp --dport 22 -j ACCEPT
iptables -A OUTPUT -d <analyst_ip> -p tcp --sport 22 -j ACCEPT
iptables -A INPUT  -j DROP
iptables -A OUTPUT -j DROP

# Windows
New-NetFirewallRule -DisplayName "Allow Analyst" -Direction Inbound -RemoteAddress <analyst_ip> -Action Allow
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block
```

### Record containment

```text
intel_update(category="host", id="web01",
  fields="status: contained\nnotes: Blocked C2 185.x.x.x, killed PID 4523, attacker session terminated",
  summary="web01 contained")
```

---

## Eradicate

Remove persistence only **after** documenting it. Snapshot state first when feasible.

Type `/eradicate <session>` for a guided workflow.

### Linux

```bash
# Cron — document before removing
crontab -l -u <user>
crontab -r -u <user>    # full removal, or edit /var/spool/cron/crontabs/<user> for one entry
rm /etc/cron.d/<malicious_file>

# systemd unit
systemctl stop <unit>; systemctl disable <unit>; systemctl mask <unit>
rm /etc/systemd/system/<unit>.service; systemctl daemon-reload

# SSH authorized_keys — edit file, remove attacker key
nano /root/.ssh/authorized_keys

# Shell profile hook
rm /etc/profile.d/<malicious>.sh    # or edit and remove the specific lines
```

### Windows

```powershell
# Scheduled task — export evidence first
Get-ScheduledTask -TaskName "<name>" | Export-Clixml "evidence-task.xml"
Disable-ScheduledTask -TaskName "<name>"
Unregister-ScheduledTask -TaskName "<name>" -Confirm:$false

# Service — export evidence first
Get-Service "<name>" | Export-Clixml "evidence-svc.xml"
Stop-Service "<name>"; Set-Service "<name>" -StartupType Disabled; sc.exe delete "<name>"

# Registry Run key
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Export-Clixml "evidence-runkey.xml"
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "<name>"

# WMI subscription (PowerShell 7)
Get-CimInstance -Namespace root/subscription -ClassName __EventFilter |
  Where-Object { $_.Name -match "<name>" } | Remove-CimInstance
Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer |
  Where-Object { $_.Name -match "<name>" } | Remove-CimInstance
Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding |
  Where-Object { $_.Filter.Name -match "<name>" } | Remove-CimInstance
```

### macOS

```bash
# LaunchDaemon / LaunchAgent
launchctl bootout system /Library/LaunchDaemons/<name>.plist
launchctl bootout gui/<uid> /Library/LaunchAgents/<name>.plist
mv /Library/LaunchDaemons/<name>.plist /tmp/evidence-<name>.plist    # preserve evidence

# Login items (macOS 13+)
sfltool dumpbtm    # list registered items before removal
osascript -e 'tell application "System Events" to delete login item "<name>"'
```

### Force credential rotation

```text
intel_query(query_type="all_credentials")
# Coordinate rotation of each active credential with your identity team, then record:
intel_update(category="credential", id="admin-ntlm",
  fields="status: rotated",
  summary="Domain admin password reset by identity team")
```

---

## Verify

Post-eradication checks. Re-run first-look then targeted verification.

Type `/verify <session>` for a post-action check pack.

### Persistence is gone

```bash
# Linux
systemctl list-units --type=service --state=running | grep -i <name>
crontab -l -u <user> 2>/dev/null | grep <pattern>

# Windows
schtasks /query /tn "<name>" 2>&1    # expect: "ERROR: The system cannot find the file"
Get-Service "<name>" -ErrorAction SilentlyContinue    # expect: no output

# macOS
launchctl list | grep <name>
```

### No C2 reconnection

```bash
# Linux
ss -tunap | grep ESTABLISHED | grep -v '<analyst_ip>'

# Windows
Get-NetTCPConnection -State Established |
  Where-Object { $_.RemoteAddress -ne '<analyst_ip>' } |
  Select-Object RemoteAddress, RemotePort, OwningProcess

# macOS
netstat -an | grep ESTABLISHED | grep -v '<analyst_ip>'
```

### Account is disabled

```bash
# Linux — check for '!' prefix in /etc/shadow
getent shadow <user> | cut -d: -f2 | head -c1    # '!' means locked

# Windows
net user <user> | findstr /I "active"    # expect: "Account active: No"
Get-ADUser -Identity <user> -Properties Enabled | Select-Object Name, Enabled

# macOS
dscl . -read /Users/<user> AuthenticationAuthority
```

### Firewall rule holds

```bash
# Linux
iptables -L OUTPUT -n | grep <c2_ip>

# Windows
Get-NetFirewallRule -DisplayName "Block C2*" | Get-NetFirewallAddressFilter

# macOS
pfctl -sr | grep <c2_ip>
```

### Record cleared

```text
intel_update(category="host", id="web01",
  fields="status: cleared\nnotes: Re-triage clean — persistence removed, C2 silent, credentials rotated",
  summary="web01 cleared after full eradication")
```

---

## Tool quick reference

| Need | Tool |
|------|------|
| Connect to host | `remote_connect` |
| Run a command on a session | `remote_exec` |
| Upload a script to the target | `remote_upload` |
| List active sessions and tunnels | `remote_sessions` |
| Disconnect a session | `remote_disconnect` |
| SSH tunnel or SOCKS proxy | `remote_tunnel` |
| Close a tunnel | `remote_tunnel_close` |
| TCP relay through a non-SSH pivot | `remote_relay` |
| Close a relay | `remote_relay_close` |
| Record a finding | `intel_add` |
| Update lifecycle or status | `intel_update` |
| Find credentials valid on a host | `intel_query(query_type="for_host", target="...")` |
| Find hosts where a cred works | `intel_query(query_type="for_credential", target="...")` |
| List all credentials | `intel_query(query_type="all_credentials")` |
| Retrieve a password / hash / key path | `intel_get_cred(id="...")` |
| Overview of all intel | `intel_summary` |
| Record a standalone event | `intel_timeline(action="add", ...)` |
| Log an operator action | `ir-log <description>` |
| Scan a network segment | `nmap -Pn -sT --open -p 22,445,3389,5985 <target>` |
| Validate credentials at scale | `netexec smb <range> -u <user> -H <hash> --no-bruteforce` |
| Dump credentials remotely | `secretsdump.py -hashes :<hash> <domain>/<user>@<target>` |
| Get a shell with a hash | `psexec.py -hashes :<hash> <domain>/<user>@<target>` |
| Route tools through a pivot | `proxychains <tool>` (after `remote_tunnel(type="dynamic", ...)`) |
| Generate an intel_add payload | `bin/intel-snippet <subcommand> ...` |

---

## Decision heuristics

### Go deeper vs. move on

- Found credentials → validate against all other known hosts before moving on
- Found persistence but no credentials → look harder; the attacker needed creds to get there
- Host is noisy or actively in use by attacker → prioritize volatile collection before state changes

### When to contain

- You've mapped the credential blast radius
- Attacker is actively exfiltrating or escalating
- You're confident they can't pivot to an unmapped host
- Incident commander says go

### Pivot method selection

| Situation | Method |
|-----------|--------|
| Target directly reachable | `remote_connect` directly |
| Pivot has SSH; one service (WinRM, SMB, RDP) | `remote_tunnel(type="local")` |
| Pivot has SSH; routing many tools | `remote_tunnel(type="dynamic")` + proxychains |
| Pivot is Windows without SSH | `remote_relay(method="netsh-portproxy")` |
| Pivot is Linux without SSH | `remote_relay` — socat or ncat |

### Where to run tools

| Task | Run from |
|------|---------|
| Credential validation (`netexec`, `secretsdump`) | Harness |
| Credential dumping (`reg save`, `cat /etc/shadow`) | On target |
| Network scanning | Harness (through SOCKS if needed) |
| Process or session kill | On target |
| Firewall rules | On target |
| Binary execution | Harness only — never drop tools on targets |

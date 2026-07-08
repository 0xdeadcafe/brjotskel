# Lateral Movement Detection — Cross-Platform Commands

> Sources: Blue Team Field Manual, RTFM v3, MITRE ATT&CK Lateral Movement (TA0008)

---

## Windows Lateral Movement Artifacts

### Remote Desktop (T1021.001)

```powershell
# RDP logon events (LogonType 10 = RemoteInteractive, 7 = Unlock)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 500 |
  Where-Object { $_.Properties[8].Value -in @(10, 7) } |
  ForEach-Object {
    [PSCustomObject]@{
      Time = $_.TimeCreated
      User = "$($_.Properties[6].Value)\$($_.Properties[5].Value)"
      SourceIP = $_.Properties[18].Value
      LogonType = $_.Properties[8].Value
    }
  } | Sort-Object Time -Descending

# RDP connection attempts (TerminalServices-RemoteConnectionManager)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id=1149} -MaxEvents 30 -EA 0 |
  ForEach-Object {
    [PSCustomObject]@{Time=$_.TimeCreated; User=$_.Properties[0].Value; Domain=$_.Properties[1].Value; SourceIP=$_.Properties[2].Value}
  }

# RDP session reconnections
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id=25} -MaxEvents 30 -EA 0
```

```cmd
:: RDP bitmap cache (evidence of RDP sessions from this host)
dir "%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache\*.bmc" 2>nul

:: RDP connection history (MRU)
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s
reg query "HKCU\Software\Microsoft\Terminal Server Client\Default" /s
```

### SMB/Windows Admin Shares (T1021.002)

```powershell
# Active SMB sessions to this host
Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens, SecondsExists

# SMB share access
Get-SmbOpenFile | Select-Object ClientComputerName, ClientUserName, Path

# Event 5140 — share accessed
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5140} -MaxEvents 30 -EA 0 |
  ForEach-Object {
    [PSCustomObject]@{
      Time = $_.TimeCreated
      Account = $_.Properties[1].Value
      Source = $_.Properties[5].Value
      ShareName = $_.Properties[6].Value
    }
  }

# Detect pass-the-hash (LogonType 3 + NTLM)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 500 |
  Where-Object { $_.Properties[8].Value -eq 3 -and $_.Properties[14].Value -eq 'NTLM' } |
  ForEach-Object {
    [PSCustomObject]@{
      Time = $_.TimeCreated
      User = $_.Properties[5].Value
      Source = $_.Properties[18].Value
      AuthPackage = $_.Properties[14].Value
    }
  } | Sort-Object Time -Descending | Select-Object -First 20
```

```cmd
:: Check admin shares exist
net share | findstr "$"

:: Active sessions (inbound)
net session

:: Open files on shares
net file

:: Mapped drives (outbound from this host)
net use
```

### PsExec / Remote Services (T1021.002, T1569.002)

```powershell
# PsExec service creation (look for PSEXESVC)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 50 -EA 0 |
  Where-Object { $_.Properties[0].Value -match 'PSEXE|RemCom|csexec|PAExec' } |
  ForEach-Object {
    [PSCustomObject]@{Time=$_.TimeCreated; Service=$_.Properties[0].Value; Path=$_.Properties[1].Value; Account=$_.Properties[4].Value}
  }

# Any new service installations
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 20 -EA 0 |
  ForEach-Object {
    [PSCustomObject]@{Time=$_.TimeCreated; Service=$_.Properties[0].Value; Path=$_.Properties[1].Value; Account=$_.Properties[4].Value}
  }

# Named pipes (PsExec and many C2 use named pipes)
Get-ChildItem \\.\pipe\ | Where-Object { $_.Name -match 'psexe|comnap|msse-|msagent_|postex' } | Select-Object Name
```

### WMI (T1021.003)

```powershell
# WMI process creation events (Sysmon Event 1 with WmiPrvSE parent)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 200 -EA 0 |
  Where-Object { $_.Properties[20].Value -match 'WmiPrvSE' } |
  ForEach-Object {
    [PSCustomObject]@{Time=$_.TimeCreated; Image=$_.Properties[4].Value; CommandLine=$_.Properties[10].Value; User=$_.Properties[12].Value}
  }

# WMI activity log
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'} -MaxEvents 30 -EA 0 |
  Select-Object TimeCreated, Id, Message
```

```cmd
:: Remote WMI execution evidence
wevtutil qe "Microsoft-Windows-WMI-Activity/Operational" /c:20 /f:text /rd:true
```

### WinRM / PowerShell Remoting (T1021.006)

```powershell
# WinRM connection events
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WinRM/Operational'; Id=6,91} -MaxEvents 20 -EA 0 |
  Select-Object TimeCreated, Id, Message

# PowerShell remoting sessions
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4103,4104,53504} -MaxEvents 50 -EA 0 |
  Where-Object { $_.Message -match 'remoting|WSMan' } | Select-Object TimeCreated, Message

# Active PS sessions
Get-PSSession

# WSMan shell instances
Get-WSManInstance -ResourceURI shell -Enumerate -EA 0
```

### DCOM (T1021.003)

```powershell
# DCOM launch events
Get-WinEvent -FilterHashtable @{LogName='System'; Id=10016} -MaxEvents 20 -EA 0 |
  Select-Object TimeCreated, @{N='CLSID';E={$_.Properties[3].Value}}, @{N='User';E={$_.Properties[6].Value}}
```

### Pass-the-Hash / Pass-the-Ticket (T1550)

```powershell
# Logon Type 9 (NewCredentials — runas /netonly, mimikatz pth)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 200 |
  Where-Object { $_.Properties[8].Value -eq 9 } |
  ForEach-Object {
    [PSCustomObject]@{Time=$_.TimeCreated; User=$_.Properties[5].Value; Process=$_.Properties[9].Value; Source=$_.Properties[18].Value}
  }

# Kerberos ticket events
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4768,4769,4770} -MaxEvents 50 -EA 0 |
  Select-Object TimeCreated, Id, @{N='Account';E={$_.Properties[0].Value}}, @{N='Service';E={$_.Properties[2].Value}}, @{N='SourceIP';E={$_.Properties[9].Value}}

# Overpass-the-hash indicator (4624 + LogonType 9 + RC4 encryption)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 200 -EA 0 |
  Where-Object { $_.Properties[5].Value -eq '0x17' } |  # RC4_HMAC
  ForEach-Object { [PSCustomObject]@{Time=$_.TimeCreated; Account=$_.Properties[0].Value; Service=$_.Properties[2].Value; Encryption='RC4'} }
```

---

## Linux Lateral Movement Artifacts

### SSH (T1021.004)

```bash
# SSH login history
grep "Accepted" /var/log/auth.log 2>/dev/null | tail -30
journalctl -u sshd | grep "Accepted" | tail -30

# Failed SSH from specific IPs
grep "Failed password" /var/log/auth.log 2>/dev/null | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20

# SSH keys used
grep "Accepted publickey" /var/log/auth.log 2>/dev/null | tail -20

# SSH agent forwarding (enables pivoting)
grep "agent" /var/log/auth.log 2>/dev/null

# Outbound SSH from this host (lateral movement FROM here)
grep -h "ssh" /root/.bash_history /home/*/.bash_history 2>/dev/null
ss -tnp | grep ":22" | grep -v "LISTEN"

# SSH config manipulation
find / -name "sshd_config" -mtime -7 2>/dev/null
find / -name "authorized_keys" -mtime -7 2>/dev/null
```

### Remote Commands (T1021.004)

```bash
# History of remote commands
grep -hE "ssh|scp|rsync|ansible|pssh|pdsh" /root/.bash_history /home/*/.bash_history 2>/dev/null

# Ansible/Puppet/Chef runs
find /var/log -name "*ansible*" -o -name "*puppet*" -o -name "*chef*" 2>/dev/null
journalctl | grep -iE "ansible|puppet|chef" | tail -20
```

### Internal Network Scanning

```bash
# Evidence of scanning tools in history
grep -hE "nmap|masscan|zmap|ping.*-c|arp-scan" /root/.bash_history /home/*/.bash_history 2>/dev/null

# Evidence of scanning in network connections
ss -tn | awk '{print $5}' | cut -d: -f2 | sort -n | uniq -c | sort -rn | head -20
# Many connections to same port = potential scanning

# Netcat / socat usage
grep -hE "nc |ncat |socat " /root/.bash_history /home/*/.bash_history 2>/dev/null
ps aux | grep -E "nc |ncat |socat " | grep -v grep
```

### Pivoting Indicators

```bash
# SSH tunnels active
ps aux | grep "ssh.*-[LRD]" | grep -v grep

# Port forwarding
ss -tlnp | grep ssh
iptables -t nat -L -n 2>/dev/null | grep -i "dnat\|redirect"

# Proxy usage
env | grep -i proxy
cat /etc/proxychains*.conf 2>/dev/null
grep -h "proxy\|socks" /root/.bash_history /home/*/.bash_history 2>/dev/null
```

---

## Detection Summary Matrix

| Technique | Windows Artifact | Linux Artifact |
|-----------|-----------------|----------------|
| RDP | Event 4624 (Type 10), TermServ logs | N/A (use VNC/X11 logs) |
| SMB/Admin Share | Event 5140, net session | smbclient logs, /var/log/samba |
| PsExec | Event 7045 (PSEXESVC), named pipes | N/A |
| WMI | WMI-Activity log, WmiPrvSE parent | N/A |
| WinRM/PSRemoting | WinRM Operational log, Event 6/91 | N/A |
| SSH | N/A (or OpenSSH for Windows) | auth.log "Accepted", key-based |
| Pass-the-Hash | Event 4624 (Type 3/9, NTLM) | N/A |
| Kerberoasting | Event 4769 (RC4 encryption) | N/A |
| Scanning | Firewall logs, many outbound SYN | ss connection patterns, tool history |
| Pivoting | netsh portproxy | SSH -L/-R/-D, socat, iptables NAT |

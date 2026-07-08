# Living off the Land — Native Tool Reference

> This skill generates commands using ONLY built-in OS tools. This reference
> documents what native utilities can accomplish for both investigation AND
> understanding attacker tradecraft (LOLBAS / GTFOBins awareness).

---

## Guiding Principle

**Never corrupt the host.** Every command this skill produces must:
1. Use tools already present on the OS (no downloads, no uploads, no installs)
2. Leave no new files on disk unless explicitly collecting evidence to a designated output path
3. Not modify system state (read-only investigation unless containment is approved)

---

## Windows Native Tools for IR

### Built-in Binaries (Always Available)

| Tool | IR Use | Location |
|------|--------|----------|
| `powershell.exe` / `pwsh.exe` | Scripting, WMI, event logs, registry | System32 |
| `cmd.exe` | Basic commands, batch scripting | System32 |
| `wmic.exe` | Process, service, user, hotfix queries | System32 |
| `wevtutil.exe` | Event log query and export | System32 |
| `netstat.exe` | Network connections | System32 |
| `tasklist.exe` | Process listing | System32 |
| `sc.exe` | Service management | System32 |
| `reg.exe` | Registry query/export | System32 |
| `schtasks.exe` | Scheduled task query | System32 |
| `net.exe` / `net1.exe` | Users, groups, shares, sessions | System32 |
| `ipconfig.exe` | Network config, DNS cache | System32 |
| `arp.exe` | ARP table | System32 |
| `route.exe` | Routing table | System32 |
| `netsh.exe` | Firewall, portproxy, WiFi, tracing | System32 |
| `certutil.exe` | File hashing, certificate inspection | System32 |
| `findstr.exe` | Text search (grep equivalent) | System32 |
| `where.exe` | Find files in PATH | System32 |
| `icacls.exe` | File permissions | System32 |
| `whoami.exe` | Current user, privileges, groups | System32 |
| `query.exe` | User sessions (RDP) | System32 |
| `qwinsta.exe` | Remote desktop sessions | System32 |
| `fsutil.exe` | File system info, USN journal | System32 |
| `cipher.exe` | EFS info, secure delete | System32 |
| `robocopy.exe` | File collection with ACL preservation | System32 |
| `xcopy.exe` | File collection | System32 |
| `forfiles.exe` | Find files by date | System32 |
| `openfiles.exe` | Open file handles | System32 |
| `auditpol.exe` | Audit policy query | System32 |
| `w32tm.exe` | Time sync status (timeline validation) | System32 |
| `bcdedit.exe` | Boot configuration | System32 |
| `driverquery.exe` | Loaded drivers | System32 |
| `pktmon.exe` | Packet capture (Win10+) | System32 |
| `tracert.exe` | Traceroute | System32 |
| `nslookup.exe` | DNS resolution | System32 |
| `bitsadmin.exe` | BITS transfer query (detect persistence) | System32 |

### PowerShell Built-in Modules (No Install Required)

| Cmdlet / Module | Purpose |
|----------------|---------|
| `Get-Process` | Process listing |
| `Get-Service` | Service enumeration |
| `Get-NetTCPConnection` | Network connections (replaces netstat) |
| `Get-NetUDPEndpoint` | UDP listeners |
| `Get-DnsClientCache` | DNS cache |
| `Get-NetNeighbor` | ARP table |
| `Get-NetRoute` | Routing table |
| `Get-NetFirewallRule` | Firewall rules |
| `Get-ScheduledTask` | Scheduled tasks |
| `Get-LocalUser` / `Get-LocalGroupMember` | User/group enum |
| `Get-WinEvent` | Event log queries |
| `Get-CimInstance` | WMI queries (Win32_Process, etc.) |
| `Get-ItemProperty` | Registry values |
| `Get-ChildItem` | File listing with filters |
| `Get-FileHash` | SHA256/MD5 hashing |
| `Get-AuthenticodeSignature` | Digital signature verification |
| `Get-HotFix` | Installed patches |
| `Get-SmbShare` / `Get-SmbSession` | SMB enumeration |
| `Get-Acl` | Permission queries |
| `Get-Content` | File reading |
| `Select-String` | Pattern matching (grep) |
| `Get-WmiObject` | WMI subscription queries |
| `Get-BitsTransfer` | BITS job queries |
| `Get-ComputerInfo` | System information |
| `Test-NetConnection` | Port/connectivity testing |
| `Resolve-DnsName` | DNS resolution |
| `Get-PSReadLineOption` | PowerShell history path |

---

## Linux Native Tools for IR

### Standard Utilities (POSIX / Common Distros)

| Tool | IR Use |
|------|--------|
| `ps` | Process listing |
| `top` / `htop` | Real-time process monitoring |
| `ss` / `netstat` | Network connections |
| `lsof` | Open files, network connections by process |
| `find` | File search by time, permissions, name |
| `grep` / `egrep` | Pattern search in files/output |
| `awk` / `sed` | Text processing and extraction |
| `cat` / `less` / `head` / `tail` | File reading |
| `ls` / `stat` | File metadata, timestamps |
| `file` | File type identification |
| `strings` | Extract printable strings from binaries |
| `sha256sum` / `md5sum` | File hashing |
| `who` / `w` / `last` / `lastb` | Login history |
| `id` / `whoami` / `groups` | Current user context |
| `crontab` | Cron job listing |
| `systemctl` / `service` | Service management |
| `journalctl` | Systemd journal queries |
| `dmesg` | Kernel messages |
| `ip` / `ifconfig` | Network interfaces |
| `iptables` / `nft` | Firewall rules |
| `mount` / `df` | Mounted filesystems |
| `lsmod` / `modinfo` | Kernel modules |
| `uname` | System/kernel info |
| `env` / `printenv` | Environment variables |
| `strace` | System call tracing |
| `ltrace` | Library call tracing |
| `tcpdump` | Packet capture |
| `openssl` | Certificate inspection, hashing |
| `dig` / `nslookup` / `host` | DNS queries |
| `arp` | ARP table |
| `route` | Routing table |
| `lsattr` / `chattr` | Extended file attributes |
| `getfacl` | ACL queries |
| `getcap` | File capabilities |
| `ausearch` / `aureport` | Audit log queries (if auditd) |
| `dpkg` / `rpm` | Package verification |
| `debsums` | Debian package integrity |

---

## Abused Native Binary Detection

Native tools can be abused by attackers. This safe corpus focuses on detection and administration, not execution of abuse patterns. Use EDR, SIEM, or vendor documentation for comprehensive abused-binary analytics.

---

## What This Skill Will NOT Generate

The following require external tools and are OUT OF SCOPE. If the analyst
needs these capabilities, direct them to the appropriate skill:

| Need | Why Out of Scope | Alternative |
|------|-----------------|-------------|
| Full memory dump | Requires LiME, WinPmem, DumpIt | Use EDR live response or `investigate-mde` |
| LSASS credential dump | Requires Mimikatz or procdump | Use EDR to collect investigation package |
| Network scanning | Requires nmap, masscan | Use existing asset inventory or EDR host search |
| Malware detonation | Requires sandbox | Use `triage-malware` skill |
| Disk imaging | Requires dd + external storage or FTK | Physical response procedure |
| Volatility analysis | Requires Volatility framework | Use `memory-forensics` skill |
| Deep packet inspection | Requires Wireshark/tshark on host | Use `tshark` skill on collected PCAP |

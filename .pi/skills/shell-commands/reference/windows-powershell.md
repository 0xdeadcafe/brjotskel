# PowerShell — Security Investigation & Incident Response Commands

> Sources: Blue Team Field Manual, RTFM v3, infosecmatter.com Pure PowerShell Infosec Cheatsheet, 55 PowerShell Hacks, Ridgeline Cyber Windows Forensic Commands

---

## System Information & Triage

```powershell
# System overview
Get-ComputerInfo | Select-Object CsName, OsName, OsVersion, OsBuildNumber, OsArchitecture, OsInstallDate, LogonServer

# Uptime
(Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime

# Environment variables
Get-ChildItem Env: | Sort-Object Name

# Installed hotfixes / patches
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object HotFixID, Description, InstalledOn

# Installed software
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object InstallDate -Descending

# PowerShell version and execution policy
$PSVersionTable
Get-ExecutionPolicy -List
```

## Process Investigation

```powershell
# All running processes with command line
Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine, CreationDate |
  Sort-Object CreationDate -Descending | Format-Table -Wrap

# Process tree — parent/child relationships
Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine |
  ForEach-Object { [PSCustomObject]@{PID=$_.ProcessId; PPID=$_.ParentProcessId; Name=$_.Name; Cmd=$_.CommandLine} }

# Find suspicious processes (encoded commands, unusual paths)
Get-CimInstance Win32_Process | Where-Object {
  $_.CommandLine -match '(-enc|-encoded|-e )' -or
  $_.CommandLine -match '(FromBase64|IEX|Invoke-Expression|downloadstring|Net\.WebClient)' -or
  $_.ExecutablePath -match '(\\Temp\\|\\AppData\\|\\ProgramData\\)'
} | Select-Object ProcessId, Name, CommandLine

# Processes with network connections
Get-NetTCPConnection -State Established | ForEach-Object {
  $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
  [PSCustomObject]@{
    LocalAddr = $_.LocalAddress; LocalPort = $_.LocalPort
    RemoteAddr = $_.RemoteAddress; RemotePort = $_.RemotePort
    PID = $_.OwningProcess; ProcessName = $proc.ProcessName
    Path = $proc.Path
  }
} | Format-Table -AutoSize

# Unsigned or suspicious DLLs loaded
Get-Process | ForEach-Object {
  $_.Modules | Where-Object { $_.FileName -and !(Get-AuthenticodeSignature $_.FileName).Status -eq 'Valid' }
} | Select-Object FileName -Unique

# Process start time analysis (find recently spawned)
Get-Process | Where-Object { $_.StartTime -gt (Get-Date).AddHours(-1) } |
  Select-Object Id, ProcessName, StartTime, Path | Sort-Object StartTime
```

## Network Investigation

```powershell
# Active TCP connections
Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } |
  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, State |
  Sort-Object RemoteAddress

# Listening ports
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess |
  ForEach-Object { $p = Get-Process -Id $_.OwningProcess -EA 0; $_ | Add-Member -NotePropertyName ProcessName -NotePropertyValue $p.ProcessName -PassThru } |
  Sort-Object LocalPort

# UDP listeners
Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess |
  ForEach-Object { $p = Get-Process -Id $_.OwningProcess -EA 0; $_ | Add-Member -NotePropertyName ProcessName -NotePropertyValue $p.ProcessName -PassThru }

# DNS cache
Get-DnsClientCache | Select-Object Entry, RecordName, RecordType, Data, TimeToLive |
  Sort-Object Entry

# ARP table
Get-NetNeighbor | Where-Object { $_.State -ne 'Unreachable' } |
  Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias

# Firewall rules (enabled)
Get-NetFirewallRule -Enabled True | Select-Object DisplayName, Direction, Action, Profile |
  Sort-Object Direction, DisplayName

# Network shares
Get-SmbShare | Select-Object Name, Path, Description
Get-SmbConnection | Select-Object ServerName, ShareName, UserName, Credential

# Route table
Get-NetRoute | Where-Object { $_.DestinationPrefix -ne '0.0.0.0/0' } |
  Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric

# WiFi profiles and passwords (requires admin)
netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
  $name = ($_ -split ':')[1].Trim()
  $details = netsh wlan show profile name="$name" key=clear
  [PSCustomObject]@{ Profile=$name; Key=($details | Select-String "Key Content" | ForEach-Object { ($_ -split ':')[1].Trim() }) }
}
```

## User & Account Investigation

```powershell
# Local users
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, Description

# Local admins
Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass, PrincipalSource

# Currently logged-in users
query user
Get-CimInstance Win32_LoggedOnUser | Select-Object -ExpandProperty Antecedent |
  Select-Object Domain, Name -Unique

# User profiles on disk
Get-CimInstance Win32_UserProfile | Select-Object LocalPath, LastUseTime, Loaded |
  Sort-Object LastUseTime -Descending

# AD user details (if domain-joined)
Get-ADUser -Filter * -Properties LastLogonDate, PasswordLastSet, Enabled, LockedOut |
  Select-Object SamAccountName, Enabled, LastLogonDate, PasswordLastSet, LockedOut

# Recently created local accounts
Get-LocalUser | Where-Object { $_.PasswordLastSet -gt (Get-Date).AddDays(-30) } |
  Select-Object Name, Enabled, PasswordLastSet

# Failed logon events (Security log, Event ID 4625)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 50 |
  ForEach-Object {
    [PSCustomObject]@{
      Time = $_.TimeCreated
      Account = $_.Properties[5].Value
      Source = $_.Properties[19].Value
      Status = $_.Properties[7].Value
    }
  } | Format-Table -AutoSize

# Successful logons (Event ID 4624)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 50 |
  ForEach-Object {
    [PSCustomObject]@{
      Time = $_.TimeCreated
      Account = $_.Properties[5].Value
      LogonType = $_.Properties[8].Value
      Source = $_.Properties[18].Value
    }
  } | Format-Table -AutoSize
```

## Persistence Mechanisms

```powershell
# Scheduled tasks (non-Microsoft)
Get-ScheduledTask | Where-Object { $_.Author -notmatch 'Microsoft' -and $_.State -ne 'Disabled' } |
  Select-Object TaskName, TaskPath, Author, Date, State |
  Format-Table -AutoSize

# Scheduled task actions (what they run)
Get-ScheduledTask | Where-Object { $_.Author -notmatch 'Microsoft' } | ForEach-Object {
  $actions = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
  [PSCustomObject]@{
    TaskName = $_.TaskName
    Execute = ($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments })
    LastRun = $actions.LastRunTime
  }
}

# Startup items (registry Run keys)
$paths = @(
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
)
$paths | ForEach-Object {
  if (Test-Path $_) { Get-ItemProperty $_ | Select-Object PSPath, * -ExcludeProperty PS* }
}

# Services (non-standard)
Get-CimInstance Win32_Service | Where-Object {
  $_.PathName -notmatch 'System32|SysWOW64' -and $_.State -eq 'Running'
} | Select-Object Name, DisplayName, State, StartMode, PathName

# WMI event subscriptions (persistence)
Get-WMIObject -Namespace root\Subscription -Class __EventFilter
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding

# Startup folder contents
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -Force
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -Force

# Browser extensions (Chrome)
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions" -Directory |
  ForEach-Object { Get-Content "$($_.FullName)\*\manifest.json" -ErrorAction SilentlyContinue | ConvertFrom-Json | Select-Object name, version, description }

# COM object hijacking check
Get-ItemProperty 'HKCU:\Software\Classes\CLSID\*\InprocServer32' -ErrorAction SilentlyContinue |
  Where-Object { $_.'(default)' -and $_.'(default)' -notmatch 'System32|SysWOW64' }
```

## File System Investigation

```powershell
# Recently modified files
Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) -and !$_.PSIsContainer } |
  Select-Object FullName, LastWriteTime, Length | Sort-Object LastWriteTime -Descending | Select-Object -First 50

# Find executables in temp/user directories
Get-ChildItem -Path $env:TEMP, $env:APPDATA, "C:\ProgramData" -Recurse -Include *.exe,*.dll,*.ps1,*.bat,*.vbs,*.js -Force -ErrorAction SilentlyContinue |
  Select-Object FullName, CreationTime, LastWriteTime, Length | Sort-Object CreationTime -Descending

# Alternate Data Streams
Get-ChildItem -Path C:\Users -Recurse -Force -ErrorAction SilentlyContinue |
  Get-Item -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne ':$DATA' }

# File hash calculation
Get-FileHash -Algorithm SHA256 -Path "C:\suspect\file.exe"
Get-ChildItem -Path C:\suspect -Recurse | Get-FileHash -Algorithm SHA256

# Find large files (possible staging/exfil)
Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue |
  Where-Object { $_.Length -gt 100MB } | Select-Object FullName, Length, LastWriteTime

# Recently created files in system directories
Get-ChildItem -Path C:\Windows\System32, C:\Windows\SysWOW64 -Force -ErrorAction SilentlyContinue |
  Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-7) } |
  Select-Object FullName, CreationTime | Sort-Object CreationTime -Descending

# Prefetch files (execution evidence)
Get-ChildItem C:\Windows\Prefetch\*.pf | Select-Object Name, LastWriteTime |
  Sort-Object LastWriteTime -Descending | Select-Object -First 20

# Recycle bin contents
(New-Object -ComObject Shell.Application).NameSpace(0x0a).Items() |
  Select-Object Name, Path, Size, ModifyDate
```

## Event Log Analysis

```powershell
# Security log — recent events summary
Get-WinEvent -LogName Security -MaxEvents 100 | Group-Object Id |
  Select-Object Name, Count | Sort-Object Count -Descending

# PowerShell script block logging (Event ID 4104)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 50 |
  Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}} | Format-List

# Service installations (Event ID 7045)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 20 |
  ForEach-Object {
    [PSCustomObject]@{
      Time = $_.TimeCreated
      ServiceName = $_.Properties[0].Value
      ImagePath = $_.Properties[1].Value
      AccountName = $_.Properties[4].Value
    }
  }

# Log clearing events (Event ID 1102)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Message

# RDP logons (Event ID 4624, LogonType 10)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 500 |
  Where-Object { $_.Properties[8].Value -eq 10 } |
  ForEach-Object {
    [PSCustomObject]@{
      Time = $_.TimeCreated
      User = $_.Properties[5].Value
      SourceIP = $_.Properties[18].Value
    }
  }

# Process creation events (Event ID 4688) — requires audit policy
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 100 |
  ForEach-Object {
    [PSCustomObject]@{
      Time = $_.TimeCreated
      NewProcess = $_.Properties[5].Value
      CommandLine = $_.Properties[8].Value
      ParentProcess = $_.Properties[13].Value
      User = $_.Properties[1].Value
    }
  } | Format-Table -AutoSize

# Defender detections
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117} -MaxEvents 20 |
  Select-Object TimeCreated, Message

# Sysmon (if installed) — Process Create (Event ID 1)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 50 |
  ForEach-Object {
    [PSCustomObject]@{
      Time = $_.TimeCreated
      Image = $_.Properties[4].Value
      CommandLine = $_.Properties[10].Value
      ParentImage = $_.Properties[20].Value
      User = $_.Properties[12].Value
      Hashes = $_.Properties[17].Value
    }
  }

# Sysmon — Network Connect (Event ID 3)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} -MaxEvents 50 |
  ForEach-Object {
    [PSCustomObject]@{
      Time = $_.TimeCreated
      Image = $_.Properties[4].Value
      DestIP = $_.Properties[14].Value
      DestPort = $_.Properties[16].Value
      User = $_.Properties[12].Value
    }
  }
```

## Registry Forensics

```powershell
# Common malware registry keys
$regPaths = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
  'HKLM:\SYSTEM\CurrentControlSet\Services',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
)
$regPaths | ForEach-Object { if (Test-Path $_) { Write-Host "`n=== $_ ==="; Get-ItemProperty $_ } }

# Recent USB device connections
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' |
  Select-Object FriendlyName, ContainerID, @{N='LastArrival';E={$_.Properties | Where-Object {$_.KeyName -eq 'LastArrivalDate'} }}

# AppCompatCache (Shimcache) — evidence of execution
# Requires parsing binary data from registry
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" /v AppCompatCache

# User Assist (execution frequency)
$userAssistPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
Get-ChildItem $userAssistPath -Recurse | Get-ItemProperty | Select-Object PSPath
```

## Credential & Authentication

```powershell
# Cached credentials info
cmdkey /list

# Kerberos tickets
klist

# LSASS protection status
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue

# Credential Guard status
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue

# Check for credential dumping tools
Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue -Include mimikatz*,procdump*,lazagne*,*sekurlsa*,*kiwi* |
  Select-Object FullName, CreationTime

# SAM/SYSTEM/SECURITY hive copies (evidence of cred dumping)
Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match '^(SAM|SYSTEM|SECURITY|NTDS\.dit)$' -and $_.DirectoryName -notmatch 'System32\\config' } |
  Select-Object FullName, CreationTime

# DPAPI master keys
Get-ChildItem "$env:APPDATA\Microsoft\Protect" -Recurse -Force
```

## Remote Execution & Lateral Movement Evidence

```powershell
# PSRemoting sessions
Get-PSSession
Get-WSManInstance -ResourceURI shell -Enumerate

# WinRM connections (Event ID 6)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WinRM/Operational'; Id=6} -MaxEvents 20 -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Message

# SMB sessions (who's connected to this host)
Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens

# Named pipes (used by many C2 frameworks)
Get-ChildItem \\.\pipe\ | Select-Object Name | Sort-Object Name

# Remote scheduled task creation
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, @{N='TaskName';E={$_.Properties[4].Value}}, @{N='TaskContent';E={$_.Properties[5].Value}}

# DCOM execution evidence
Get-WinEvent -FilterHashtable @{LogName='System'; Id=10016} -MaxEvents 10 -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Message
```

## Memory & Threat Hunting

```powershell
# Injected threads (basic check)
Get-Process | ForEach-Object {
  try {
    $threads = $_.Threads | Where-Object { $_.StartAddress -ne 0 }
    if ($threads.Count -gt 50) { [PSCustomObject]@{Process=$_.ProcessName; PID=$_.Id; Threads=$threads.Count} }
  } catch {}
}

# Suspicious PowerShell downloads in history
Get-Content (Get-PSReadLineOption).HistorySavePath -ErrorAction SilentlyContinue |
  Select-String -Pattern 'download|invoke-webrequest|wget|curl|iwr|Net\.WebClient|DownloadString|DownloadFile|Start-BitsTransfer'

# Find base64 encoded commands in event logs
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 200 |
  Where-Object { $_.Properties[2].Value -match '[A-Za-z0-9+/]{50,}={0,2}' } |
  Select-Object TimeCreated, @{N='Script';E={$_.Properties[2].Value.Substring(0,200)}}

# AMSI bypass attempts in logs
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 500 |
  Where-Object { $_.Properties[2].Value -match 'AmsiUtils|amsiInitFailed|AmsiScanBuffer' } |
  Select-Object TimeCreated, @{N='Script';E={$_.Properties[2].Value.Substring(0,300)}}
```

## Data Collection & Export

```powershell
# Export results to CSV
Get-Process | Export-Csv -Path "$env:TEMP\processes.csv" -NoTypeInformation

# Export event logs to EVTX
wevtutil epl Security "$env:TEMP\security.evtx"
wevtutil epl System "$env:TEMP\system.evtx"
wevtutil epl "Microsoft-Windows-PowerShell/Operational" "$env:TEMP\powershell.evtx"

# Create timeline (collect key artifacts)
$timeline = @()
$timeline += Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4688,4698,4720} -MaxEvents 500 -EA 0 |
  Select-Object TimeCreated, Id, Message
$timeline += Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045,7036} -MaxEvents 200 -EA 0 |
  Select-Object TimeCreated, Id, Message
$timeline | Sort-Object TimeCreated | Export-Csv "$env:TEMP\timeline.csv" -NoTypeInformation

# Hash all executables in a directory
Get-ChildItem -Path "C:\suspect" -Recurse -Include *.exe,*.dll,*.ps1,*.bat |
  ForEach-Object { [PSCustomObject]@{File=$_.FullName; SHA256=(Get-FileHash $_ -Algorithm SHA256).Hash; Size=$_.Length} } |
  Export-Csv "$env:TEMP\hashes.csv" -NoTypeInformation
```

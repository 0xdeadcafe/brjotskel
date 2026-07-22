# gather/windows/first-look.ps1 — 30-second situational awareness
# Requires: Standard user (admin gets more detail)
# Read-only: YES
# Footprint: Zero (no temp files, no disk writes)
# Purpose: Immediate "am I alone? what's happening right now?" before full triage
#
# Run inline: remote_exec(command="<paste>")
#
# ⚠️ SUSPICIOUS indicators are noted inline with [!]

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }

Sec 'IDENTITY & HOST'
Write-Output "Host: $env:COMPUTERNAME | Domain: $env:USERDOMAIN"
Write-Output "User: $env:USERNAME | Date: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
Write-Output "OS: $((Get-CimInstance Win32_OperatingSystem).Caption) Build $((Get-CimInstance Win32_OperatingSystem).BuildNumber)"
# Show current privilege level
whoami /priv 2>$null | Select-String 'SeDebugPrivilege|SeImpersonatePrivilege|SeTcbPrivilege|SeAssignPrimaryTokenPrivilege'

Sec 'WHO IS ON RIGHT NOW'
# [!] Unknown users, multiple sessions, sessions from unexpected IPs
query user 2>$null
# RDP sessions
qwinsta 2>$null | Where-Object { $_ -match 'Active|Disc' }

Sec 'LAST LOGONS (RECENT)'
# [!] Logons from unexpected sources, at odd hours, Type 10 (RDP) or Type 3 (network) from unknown
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 10 2>$null |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    $type = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' } | Select-Object -ExpandProperty '#text'
    $user = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' } | Select-Object -ExpandProperty '#text'
    $src  = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' } | Select-Object -ExpandProperty '#text'
    Write-Output "$($_.TimeCreated.ToString('HH:mm:ss')) Type=$type User=$user Src=$src"
  }

Sec 'TOP PROCESSES BY CPU'
# [!] Unknown binaries, processes in C:\Users\Public, C:\ProgramData\unusual, encoded names
Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 |
  Format-Table Id, ProcessName, CPU, @{L='Path';E={$_.Path}} -AutoSize

Sec 'ACTIVE NETWORK CONNECTIONS'
# [!] Outbound to unusual ports, connections to external IPs, ESTABLISHED to unknown
Get-NetTCPConnection -State Established,Listen 2>$null |
  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
  Sort-Object State, RemoteAddress |
  Format-Table -AutoSize
# Map PIDs to process names for suspicious connections
$suspPorts = @(4444,5555,6666,6667,8888,9999,1234,31337)
Get-NetTCPConnection -State Established 2>$null | Where-Object { $suspPorts -contains $_.RemotePort -or $suspPorts -contains $_.LocalPort } |
  ForEach-Object { Write-Output "[!] SUSPICIOUS PORT: $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort) PID=$($_.OwningProcess) ($((Get-Process -Id $_.OwningProcess).ProcessName))" }

Sec 'LISTENING SERVICES'
# [!] Unexpected listeners on high ports, 0.0.0.0 binds
Get-NetTCPConnection -State Listen 2>$null |
  ForEach-Object { "$($_.LocalAddress):$($_.LocalPort) PID=$($_.OwningProcess) ($((Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName))" } |
  Sort-Object

Sec 'ATTACKER STAGING AREAS'
# [!] Scripts, executables, encoded blobs in public-writable locations
$paths = @("$env:PUBLIC", "$env:TEMP", "$env:SystemRoot\Temp", "$env:ProgramData")
foreach ($p in $paths) {
  if (Test-Path $p) {
    $items = Get-ChildItem $p -File -ErrorAction SilentlyContinue | Where-Object {
      $_.Extension -match '\.(exe|ps1|bat|cmd|vbs|js|dll|hta|scr|msi|py|sh)$' -or
      $_.LastWriteTime -gt (Get-Date).AddHours(-24)
    } | Select-Object Name, Length, LastWriteTime
    if ($items) { Write-Output "--- $p ---"; $items | Format-Table -AutoSize }
  }
}

Sec 'FILES MODIFIED IN LAST HOUR'
# [!] Modified system binaries, new scripts in system paths, changed configs
$recentPaths = @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64", "$env:ProgramData", "$env:PUBLIC")
foreach ($rp in $recentPaths) {
  Get-ChildItem $rp -File -Recurse -Depth 1 -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-60) } |
    Select-Object FullName, LastWriteTime | Format-Table -AutoSize
}

Sec 'SCHEDULED TASKS (SUSPICIOUS)'
# [!] Tasks with encoded commands, tasks running as SYSTEM from user-writable paths, recently created
Get-ScheduledTask 2>$null | Where-Object { $_.State -eq 'Ready' -or $_.State -eq 'Running' } |
  ForEach-Object {
    $info = Get-ScheduledTaskInfo $_.TaskName -ErrorAction SilentlyContinue
    $actions = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
    if ($actions -match 'powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|base64|http|\\\\|C:\\Users\\Public|C:\\ProgramData') {
      Write-Output "[!] $($_.TaskName) | RunAs=$($_.Principal.UserId) | Action=$actions"
    }
  }

Sec 'SERVICES (UNUSUAL)'
# [!] Services with paths in temp/user dirs, unsigned, recently created
Get-CimInstance Win32_Service | Where-Object {
  $_.PathName -match 'Temp|Public|ProgramData\\[^M]|Users\\' -or
  $_.StartMode -eq 'Auto' -and $_.State -eq 'Stopped'
} | Select-Object Name, State, StartMode, @{L='Path';E={$_.PathName}} | Format-Table -AutoSize

Sec 'DEFENDER STATUS'
# [!] Disabled real-time protection, tampered definitions, exclusions
$mpPref = Get-MpPreference 2>$null
$mpStatus = Get-MpComputerStatus 2>$null
if ($mpStatus) {
  Write-Output "RealTimeProtection: $($mpStatus.RealTimeProtectionEnabled)"
  Write-Output "BehaviorMonitor: $($mpStatus.BehaviorMonitorEnabled)"
  Write-Output "LastFullScan: $($mpStatus.FullScanEndTime)"
  Write-Output "DefAge: $($mpStatus.AntivirusSignatureAge) days"
  if ($mpPref.ExclusionPath) { Write-Output "[!] Exclusion paths: $($mpPref.ExclusionPath -join ', ')" }
  if ($mpPref.ExclusionProcess) { Write-Output "[!] Exclusion processes: $($mpPref.ExclusionProcess -join ', ')" }
  if (-not $mpStatus.RealTimeProtectionEnabled) { Write-Output "[!] REAL-TIME PROTECTION IS DISABLED" }
}

Sec 'FIREWALL STATE'
# [!] Disabled profiles
Get-NetFirewallProfile 2>$null | ForEach-Object {
  $status = if ($_.Enabled) { "ON" } else { "[!] OFF" }
  Write-Output "$($_.Name): $status (DefaultInbound=$($_.DefaultInboundAction) DefaultOutbound=$($_.DefaultOutboundAction))"
}

Sec 'ENVIRONMENT SUMMARY'
$os = Get-CimInstance Win32_OperatingSystem
Write-Output "CPUs: $env:NUMBER_OF_PROCESSORS | RAM: $([math]::Round($os.TotalVisibleMemorySize/1MB,1))GB | Uptime: $((New-TimeSpan -Start $os.LastBootUpTime).ToString('d\.hh\:mm'))"
Write-Output ""
Write-Output "[first-look complete - run full triage for deeper analysis]"

# gather/windows/collect-evidence.ps1 — Pre-containment volatile evidence collection
# Requires: Admin (recommended before containment)
# Read-only: YES — captures state only, no modifications
# Footprint: stdout only — no files written on target
# Purpose: Bag volatile state BEFORE any containment action changes it
#
# ⚠️  RUN THIS BEFORE kill-process, block-c2, disable-account, or any network isolation
#     Process environment, live connections, and session state die when you act.
#
# Usage:
#   remote_exec(session="host01", command="<paste>") — capture output to harness
#   Pull result to: workspace/evidence/<host>/volatile-<timestamp>.txt

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n [$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))] ===" }
function HashFile($p) {
  if (Test-Path $p -PathType Leaf) {
    try { (Get-FileHash $p -Algorithm SHA256).Hash + "  $p" } catch { "HASH_ERROR  $p" }
  }
}

Sec 'EVIDENCE HEADER'
Write-Output "Host:      $env:COMPUTERNAME"
Write-Output "Domain:    $env:USERDOMAIN"
Write-Output "Collected: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
Write-Output "Collector: $env:USERNAME  ($((whoami /priv 2>$null | Select-String 'SeDebugPrivilege' | ForEach-Object { 'SeDebug=YES' }) -join ''))"
$os = Get-CimInstance Win32_OperatingSystem
Write-Output "OS:        $($os.Caption) Build $($os.BuildNumber)"
Write-Output "Uptime:    $((New-TimeSpan -Start $os.LastBootUpTime).ToString('d\.hh\:mm'))"

Sec 'PROCESS TREE — FULL COMMAND LINES'
# ⚠️  Volatile: process command line may not survive kill
Get-CimInstance Win32_Process | Sort-Object CreationDate |
  Select-Object ProcessId, ParentProcessId, Name, CommandLine, @{L='Created';E={$_.CreationDate}} |
  Format-Table -AutoSize -Wrap

Sec 'PROCESS BINARY HASHES — NON-STANDARD PATHS'
# Hash binaries outside standard OS paths BEFORE killing
Get-Process | ForEach-Object {
  try {
    $path = $_.Path
    if ($path -and $path -notmatch 'System32|SysWOW64|\\Windows\\|Program Files') {
      HashFile $path
    }
  } catch {}
} | Sort-Object -Unique

Sec 'ACTIVE NETWORK CONNECTIONS — WITH PIDS AND PROCESS NAMES'
# ⚠️  Volatile: dies at kill or isolation
Get-NetTCPConnection -State Established, Listen, TimeWait 2>$null |
  ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
      State         = $_.State
      LocalAddr     = "$($_.LocalAddress):$($_.LocalPort)"
      RemoteAddr    = "$($_.RemoteAddress):$($_.RemotePort)"
      PID           = $_.OwningProcess
      Process       = $proc.ProcessName
      Path          = $proc.Path
    }
  } | Sort-Object State, RemoteAddr | Format-Table -AutoSize

Sec 'ESTABLISHED CONNECTIONS — REMOTE ENDPOINTS (C2 CANDIDATES)'
# Quick extract of outbound remote addresses for C2 identification
Get-NetTCPConnection -State Established 2>$null |
  ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort)  PID=$($_.OwningProcess)  Proc=$((Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName)" } |
  Sort-Object -Unique

Sec 'LISTENING SERVICES SNAPSHOT'
Get-NetTCPConnection -State Listen 2>$null |
  ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)  PID=$($_.OwningProcess)  Proc=$((Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName)" } |
  Sort-Object

Sec 'ACTIVE USER SESSIONS'
# ⚠️  Session details lost after account disable or isolation
query user 2>$null
qwinsta 2>$null

Sec 'RECENT LOGON EVENTS (4624) — LAST 30'
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 30 2>$null |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    $d = @{}; $xml.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    Write-Output "$($_.TimeCreated.ToString('HH:mm:ss')) Type=$($d.LogonType) User=$($d.TargetUserName) Domain=$($d.TargetDomainName) Src=$($d.IpAddress)"
  }

Sec 'ATTACKER STAGING AREAS — FILE LISTING AND HASHES'
$stagePaths = @(
  $env:PUBLIC,
  $env:TEMP,
  "$env:SystemRoot\Temp",
  "$env:ProgramData",
  "$env:USERPROFILE\Downloads",
  "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($sp in $stagePaths) {
  if (-not (Test-Path $sp)) { continue }
  $files = Get-ChildItem $sp -File -Recurse -Depth 2 -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -match '\.(exe|dll|ps1|bat|cmd|vbs|js|hta|scr|msi|py|sh|bin|tmp)$' -or
                   $_.LastWriteTime -gt (Get-Date).AddHours(-48) }
  if ($files) {
    Write-Output "`n--- $sp ---"
    $files | ForEach-Object {
      $hash = try { (Get-FileHash $_.FullName -Algorithm SHA256 -EA Stop).Hash } catch { 'HASH_ERR' }
      Write-Output "$hash  $($_.FullName)  [$($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))]"
    }
  }
}

Sec 'RECENTLY MODIFIED SYSTEM FILES (LAST 2H)'
$sysPaths = @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64")
foreach ($sp in $sysPaths) {
  Get-ChildItem $sp -File -Depth 1 -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-2) } |
    ForEach-Object {
      $hash = try { (Get-FileHash $_.FullName -Algorithm SHA256 -EA Stop).Hash } catch { 'HASH_ERR' }
      Write-Output "$hash  $($_.FullName)  [$($_.LastWriteTime)]"
    }
}

Sec 'SCHEDULED TASKS SNAPSHOT — NON-MICROSOFT'
Get-ScheduledTask 2>$null |
  Where-Object { $_.TaskPath -notmatch '\\Microsoft\\' } |
  ForEach-Object {
    $actions = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
    Write-Output "Task: $($_.TaskPath)$($_.TaskName)"
    Write-Output "  State: $($_.State)  RunAs: $($_.Principal.UserId)"
    Write-Output "  Actions: $actions"
  }

Sec 'SERVICES — UNUSUAL PATHS'
Get-CimInstance Win32_Service |
  Where-Object { $_.PathName -and $_.PathName -notmatch 'System32|SysWOW64|Program Files|Microsoft' } |
  Select-Object Name, State, StartMode, @{L='Path';E={$_.PathName}} |
  Format-Table -AutoSize -Wrap

Sec 'PSREADLINE HISTORY — ALL USERS'
Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
  ForEach-Object {
    $hPath = "$($_.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $hPath) {
      Write-Output "`n--- $($_.Name) ---"
      Get-Content $hPath -ErrorAction SilentlyContinue | Select-Object -Last 50
    }
  }

Sec 'WMI EVENT SUBSCRIPTIONS'
Get-CimInstance -Namespace root/subscription -ClassName __EventFilter 2>$null |
  ForEach-Object { Write-Output "[Filter] $($_.Name): $($_.Query)" }
Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer 2>$null |
  ForEach-Object { Write-Output "[CmdConsumer] $($_.Name): $($_.CommandLineTemplate)" }
Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer 2>$null |
  ForEach-Object { Write-Output "[ScriptConsumer] $($_.Name)" }

Sec 'RUN KEYS SNAPSHOT'
$runKeys = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
foreach ($k in $runKeys) {
  $props = Get-ItemProperty $k -ErrorAction SilentlyContinue
  if ($props) {
    Write-Output "`n--- $k ---"
    $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } |
      ForEach-Object { Write-Output "  $($_.Name) = $($_.Value)" }
  }
}

Sec 'ARP TABLE'
Get-NetNeighbor 2>$null | Where-Object { $_.State -ne 'Unreachable' } |
  Format-Table IPAddress, LinkLayerAddress, State, InterfaceAlias -AutoSize

Sec 'DNS CACHE'
Get-DnsClientCache 2>$null | Select-Object -First 60 |
  Format-Table Entry, RecordType, Data, TimeToLive -AutoSize

Sec 'FIREWALL STATE SNAPSHOT'
Get-NetFirewallProfile 2>$null |
  Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction -AutoSize

Sec 'DEFENDER STATUS AND EXCLUSIONS'
$mpStatus = Get-MpComputerStatus 2>$null
$mpPref   = Get-MpPreference 2>$null
if ($mpStatus) {
  Write-Output "RealTimeProtection: $($mpStatus.RealTimeProtectionEnabled)"
  Write-Output "BehaviorMonitor:    $($mpStatus.BehaviorMonitorEnabled)"
  if (-not $mpStatus.RealTimeProtectionEnabled) { Write-Output "[!] REAL-TIME PROTECTION DISABLED" }
}
if ($mpPref?.ExclusionPath)    { Write-Output "[!] Exclusion paths:     $($mpPref.ExclusionPath -join ', ')" }
if ($mpPref?.ExclusionProcess) { Write-Output "[!] Exclusion processes: $($mpPref.ExclusionProcess -join ', ')" }

Sec 'EVIDENCE COLLECTION COMPLETE'
Write-Output "Timestamp: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
Write-Output "Next steps:"
Write-Output "  1. Save this output: workspace/evidence/<host>/volatile-<timestamp>.txt"
Write-Output "  2. Record C2 IPs from ESTABLISHED CONNECTIONS above"
Write-Output "  3. Hash any suspicious binaries before killing"
Write-Output "  4. Then proceed with containment"

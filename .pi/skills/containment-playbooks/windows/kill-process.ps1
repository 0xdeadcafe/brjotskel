# containment/windows/kill-process.ps1 — Evidence-first process termination
# Requires: Admin
# State-changing: YES — kills the target process
# Pattern: EVIDENCE → KILL → VERIFY
#
# Parameters (set before running):
#   $TargetPid   — PID to kill (preferred)
#   $TargetName  — process name if PID unknown (kills ALL matching — confirm first)
#
# Usage (set at top of paste or via env):
#   $TargetPid = 4523; <paste>
#   $TargetName = "implant"; <paste>
#
# ⚠️  Run collect-evidence.ps1 BEFORE this script

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }
function HashFile($p) {
  if (Test-Path $p -PathType Leaf) {
    try { (Get-FileHash $p -Algorithm SHA256 -EA Stop).Hash + "  $p" } catch { "HASH_ERROR  $p" }
  }
}

# Parameters — set these before running
if (-not $TargetPid -and -not $TargetName) {
  Write-Error "Set `$TargetPid = <pid> or `$TargetName = '<name>' before running"
  exit 1
}

# Resolve process object
$targetProc = $null
if ($TargetPid) {
  $targetProc = Get-Process -Id $TargetPid -ErrorAction Stop
} elseif ($TargetName) {
  $procs = Get-Process -Name $TargetName -ErrorAction Stop
  if ($procs.Count -gt 1) {
    Write-Output "[!] Multiple processes match '$TargetName':"
    $procs | Format-Table Id, Name, Path -AutoSize
    Write-Output "Set `$TargetPid to target a specific PID"
  }
  $targetProc = $procs | Select-Object -First 1
}

if (-not $targetProc) {
  Write-Error "Target process not found"
  exit 1
}

Sec 'PRE-KILL EVIDENCE — PROCESS STATE'
Write-Output "Timestamp: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
Write-Output "Target: PID=$($targetProc.Id) Name=$($targetProc.Name)"

Write-Output "`n--- Full command line ---"
(Get-CimInstance Win32_Process -Filter "ProcessId = $($targetProc.Id)").CommandLine

Write-Output "`n--- Executable path ---"
Write-Output $targetProc.Path

Write-Output "`n--- Binary hash ---"
HashFile $targetProc.Path

Write-Output "`n--- Process details ---"
$targetProc | Select-Object Id, Name, CPU, WorkingSet, StartTime, Path | Format-List

Write-Output "`n--- Parent process ---"
$ppid = (Get-CimInstance Win32_Process -Filter "ProcessId = $($targetProc.Id)").ParentProcessId
Get-Process -Id $ppid -ErrorAction SilentlyContinue | Select-Object Id, Name, Path | Format-Table

Write-Output "`n--- Modules loaded ---"
$targetProc.Modules 2>$null | Select-Object ModuleName, FileName | Format-Table -AutoSize | Select-Object -First 20

Write-Output "`n--- Open network connections ---"
Get-NetTCPConnection -OwningProcess $targetProc.Id 2>$null |
  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Format-Table

Write-Output "`n--- Authenticode signature ---"
Get-AuthenticodeSignature $targetProc.Path 2>$null | Select-Object Status, SignerCertificate | Format-List

Sec 'KILL'
Write-Output "Stopping PID $($targetProc.Id) ($($targetProc.Name))..."
Stop-Process -Id $targetProc.Id -Force
Start-Sleep -Seconds 2

Sec 'VERIFY — PROCESS GONE'
$check = Get-Process -Id $targetProc.Id -ErrorAction SilentlyContinue
if ($check) {
  Write-Output "[FAIL] PID $($targetProc.Id) is still running"
  $check | Format-Table Id, Name, CPU -AutoSize
  Write-Output "Manual intervention required (check for Protected Process)"
} else {
  Write-Output "[OK] PID $($targetProc.Id) ($($targetProc.Name)) is gone"
}

# Check for respawn by name
if ($TargetName) {
  $respawn = Get-Process -Name $TargetName -ErrorAction SilentlyContinue
  if ($respawn) {
    Write-Output "[!] WARNING: '$TargetName' reappeared as PID $($respawn.Id) — persistence active"
    Write-Output "Run enum-persistence.ps1 and escalate to eradication"
  } else {
    Write-Output "[OK] '$TargetName' did not respawn"
  }
}

Sec 'INTEL UPDATE SNIPPET'
Write-Output @"

intel_update(category="host", id="<HOST_ID>",
  fields="status: contained\nnotes: PID $($targetProc.Id) ($($targetProc.Name)) killed at $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))",
  summary="<HOST_ID>: PID $($targetProc.Id) killed")
"@

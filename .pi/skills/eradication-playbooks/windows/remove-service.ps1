# eradication/windows/remove-service.ps1 — Evidence-backed service removal
# Requires: Admin
# State-changing: YES — stops, disables, and deletes the service
# Pattern: EVIDENCE → STOP → DISABLE → DELETE → VERIFY
#
# Parameters:
#   $ServiceName  — service name (not display name) to remove
#
# Usage:
#   $ServiceName = "WinDefend32"; <paste>
#
# ⚠️  Containment first. Confirm this is the attacker's service before running.

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }

if (-not $ServiceName) {
  Write-Error "Set `$ServiceName = '<service name>' before running"
  exit 1
}

$svc = Get-Service -Name $ServiceName -ErrorAction Stop
$svcWmi = Get-CimInstance Win32_Service -Filter "Name = '$ServiceName'" -ErrorAction SilentlyContinue

Sec 'EVIDENCE — SERVICE STATE BEFORE REMOVAL'
Write-Output "Timestamp: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
Write-Output "Service: $ServiceName"

Write-Output "`n--- Service details ---"
$svc | Format-List *

Write-Output "`n--- WMI details (path, start mode) ---"
$svcWmi | Select-Object Name, DisplayName, State, StartMode, PathName, StartName | Format-List

# Hash the binary
$binPath = $svcWmi.PathName -replace '"','' -replace ' .*',''
if ($binPath -and (Test-Path $binPath -PathType Leaf)) {
  Write-Output "`n--- Service binary hash ---"
  (Get-FileHash $binPath -Algorithm SHA256 -EA SilentlyContinue).Hash + "  $binPath"
  Write-Output "`n--- Authenticode signature ---"
  Get-AuthenticodeSignature $binPath 2>$null | Select-Object Status, SignerCertificate | Format-List
}

Write-Output "`n--- Registry service key ---"
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -ErrorAction SilentlyContinue | Format-List

Sec 'SAVE EVIDENCE'
$evidencePath = "$env:TEMP\evidence-svc-$($ServiceName -replace '[\\/:*?"<>|]','_')-$((Get-Date).ToString('yyyyMMddTHHmmss')).xml"
$svcWmi | Export-Clixml -Path $evidencePath -ErrorAction SilentlyContinue
Write-Output "[OK] Service details exported to: $evidencePath"
Write-Output "     Pull to: workspace/evidence/<host>/service-$ServiceName.xml"

Sec 'STOP → DISABLE → DELETE'
Write-Output "--- Stop service ---"
Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
Write-Output "[OK] Stop-Service sent"

Write-Output "`n--- Disable service ---"
Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction SilentlyContinue
Write-Output "[OK] StartupType set to Disabled"

Write-Output "`n--- Delete service ---"
$result = sc.exe delete $ServiceName 2>&1
Write-Output $result
if ($result -match 'SUCCESS') { Write-Output "[OK] sc.exe delete succeeded" }
else { Write-Output "[!] sc.exe delete output above — check manually" }

Sec 'VERIFY — SERVICE GONE'
$check = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($check) {
  Write-Output "[!] Service still registered (may need reboot to fully remove): $($check.Status)"
} else {
  Write-Output "[OK] Service '$ServiceName' is gone"
}

$regCheck = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
if ($regCheck) { Write-Output "[!] Registry key still exists — may need manual removal after reboot" }
else { Write-Output "[OK] Registry key removed" }

Write-Output "`nNote: If the binary is in a staging area, remove it now:"
if ($binPath) { Write-Output "  Binary was: $binPath" }

Sec 'INTEL TIMELINE SNIPPET'
Write-Output @"

intel_timeline(action="add", entry_type="eradication", entry_action="eradicated",
  target="<HOST_ID>",
  summary="<HOST_ID>: service '$ServiceName' stopped/disabled/deleted at $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))")
"@

# eradication/windows/remove-registry-run.ps1 — Remove a malicious Run/RunOnce key entry
# Requires: Admin (for HKLM) or current user (for HKCU)
# State-changing: YES — removes registry value
# Pattern: EVIDENCE → REMOVE → VERIFY
#
# Parameters:
#   $RunKeyPath   — registry key path, e.g. "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
#   $RunValueName — name of the value to remove
#
# Usage:
#   $RunKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
#   $RunValueName = "WindowsHelper"
#   <paste>

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }

if (-not $RunKeyPath -or -not $RunValueName) {
  Write-Error "Set `$RunKeyPath and `$RunValueName before running"
  exit 1
}

Sec 'EVIDENCE — RUN KEY STATE BEFORE REMOVAL'
Write-Output "Timestamp:  $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
Write-Output "Key:        $RunKeyPath"
Write-Output "Value name: $RunValueName"

$props = Get-ItemProperty $RunKeyPath -ErrorAction Stop
$value = $props.$RunValueName
Write-Output "Value data: $value"

Write-Output "`n--- Full key contents (context) ---"
$props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } |
  ForEach-Object { Write-Output "  $($_.Name) = $($_.Value)" }

# Hash the pointed binary
$binPath = $value -replace '"','' -replace ' .*','' -replace "'",''
$binPath = $binPath.Trim()
if ($binPath -and (Test-Path $binPath -PathType Leaf)) {
  Write-Output "`n--- Binary hash ---"
  (Get-FileHash $binPath -Algorithm SHA256 -EA SilentlyContinue).Hash + "  $binPath"
  Write-Output "`n--- Authenticode signature ---"
  Get-AuthenticodeSignature $binPath 2>$null | Select-Object Status, SignerCertificate | Format-List
}

Sec 'SAVE EVIDENCE'
$evidencePath = "$env:TEMP\evidence-runkey-$($RunValueName -replace '[\\/:*?"<>|]','_')-$((Get-Date).ToString('yyyyMMddTHHmmss')).xml"
$props | Export-Clixml -Path $evidencePath -ErrorAction SilentlyContinue
Write-Output "[OK] Key contents exported to: $evidencePath"
Write-Output "     Pull to: workspace/evidence/<host>/runkey-$RunValueName.xml"

Sec 'REMOVE VALUE'
Remove-ItemProperty -Path $RunKeyPath -Name $RunValueName -ErrorAction Stop
Write-Output "[OK] Removed: $RunValueName from $RunKeyPath"

Sec 'VERIFY — VALUE GONE'
$check = (Get-ItemProperty $RunKeyPath -ErrorAction SilentlyContinue).$RunValueName
if ($null -ne $check) {
  Write-Output "[FAIL] Value '$RunValueName' still present: $check"
} else {
  Write-Output "[OK] Value '$RunValueName' is gone"
}

Write-Output "`n--- Key contents after removal ---"
(Get-ItemProperty $RunKeyPath).PSObject.Properties |
  Where-Object { $_.Name -notmatch '^PS' } |
  ForEach-Object { Write-Output "  $($_.Name) = $($_.Value)" }

Write-Output "`nNote: Run key changes take effect on next logon."
Write-Output "If binary is in a staging area, remove it:"
if ($binPath) { Write-Output "  Remove-Item -Path '$binPath' -Force" }

Sec 'INTEL TIMELINE SNIPPET'
Write-Output @"

intel_timeline(action="add", entry_type="eradication", entry_action="eradicated",
  target="<HOST_ID>",
  summary="<HOST_ID>: Run key '$RunValueName' removed from $RunKeyPath at $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))")
"@

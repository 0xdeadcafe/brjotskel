# gather/windows/enum-av-exclusions.ps1 — Enumerate AV exclusion paths, processes, and extensions
# Requires: Registry read access; fuller coverage with admin
# Read-only: YES
# MITRE ATT&CK: T1562.001

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }
function Show-Exclusions($label, $path) {
    if (Test-Path $path) {
        $props = Get-ItemProperty $path
        $rows = $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            [pscustomobject]@{ Item = $_.Name; Value = $_.Value }
        }
        if ($rows) {
            Write-Output "--- $label ---"
            $rows | Format-Table -AutoSize
        }
    }
}

Sec 'OBJECTIVE'
'Collect antivirus exclusion paths, processes, and extensions that may indicate attacker safe paths or defender tampering.'

Sec 'MICROSOFT_DEFENDER_EXCLUSIONS'
Show-Exclusions 'Defender Extensions' 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions'
Show-Exclusions 'Defender Paths' 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'
Show-Exclusions 'Defender Processes' 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes'

Sec 'MICROSOFT_ANTIMALWARE_EXCLUSIONS'
Show-Exclusions 'Microsoft Antimalware Extensions' 'HKLM:\SOFTWARE\Microsoft\Microsoft Antimalware\Exclusions\Extensions'
Show-Exclusions 'Microsoft Antimalware Paths' 'HKLM:\SOFTWARE\Microsoft\Microsoft Antimalware\Exclusions\Paths'
Show-Exclusions 'Microsoft Antimalware Processes' 'HKLM:\SOFTWARE\Microsoft\Microsoft Antimalware\Exclusions\Processes'

Sec 'SYMANTEC_ENDPOINT_PROTECTION_EXCLUSIONS'
$sepAdmin = 'HKLM:\SOFTWARE\Symantec\Symantec Endpoint Protection\Exclusions\ScanningEngines\Directory\Admin'
$sepClient = 'HKLM:\SOFTWARE\Symantec\Symantec Endpoint Protection\Exclusions\ScanningEngines\Directory\Client'
foreach ($path in @($sepAdmin, $sepClient)) {
    if (Test-Path $path) {
        Write-Output "--- $path ---"
        Get-ChildItem $path | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath
            [pscustomobject]@{ Key = $_.PSChildName; DirectoryName = $p.DirectoryName }
        } | Format-Table -AutoSize
    }
}

Sec 'DEFENDER_STATUS'
Get-MpComputerStatus | Select-Object AMRunningMode, RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, IsTamperProtected, AntivirusSignatureVersion

# gather/windows/enum-protections.ps1 — Security tool detection
# Requires: Standard user
# Read-only: YES
# MITRE ATT&CK: T1518.001 — Security Software Discovery

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }
function Run($c) { Write-Output "PS> $c"; Invoke-Expression $c }

Sec 'ANTIVIRUS_EDR_STATUS'
Run 'Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Format-Table displayName, productState, pathToSignedProductExe'

Sec 'WINDOWS_DEFENDER'
try {
    $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    Write-Output "RealTimeProtection: $($mpStatus.RealTimeProtectionEnabled)"
    Write-Output "BehaviorMonitor: $($mpStatus.BehaviorMonitorEnabled)"
    Write-Output "IoavProtection: $($mpStatus.IoavProtectionEnabled)"
    Write-Output "AntiSpyware: $($mpStatus.AntispywareEnabled)"
    Write-Output "TamperProtection: $($mpStatus.IsTamperProtected)"
    Write-Output "SignatureVersion: $($mpStatus.AntivirusSignatureVersion)"
    Write-Output "LastScan: $($mpStatus.LastFullScanEndTime)"
} catch {
    Write-Output "[*] Defender status unavailable"
}

Sec 'DEFENDER_EXCLUSIONS'
try {
    $excl = Get-MpPreference -ErrorAction SilentlyContinue
    if ($excl.ExclusionPath) { Write-Output "ExcludedPaths: $($excl.ExclusionPath -join ', ')" }
    if ($excl.ExclusionExtension) { Write-Output "ExcludedExts: $($excl.ExclusionExtension -join ', ')" }
    if ($excl.ExclusionProcess) { Write-Output "ExcludedProcs: $($excl.ExclusionProcess -join ', ')" }
} catch {}

Sec 'AMSI_PROVIDERS'
Run 'Get-ChildItem "HKLM:\SOFTWARE\Microsoft\AMSI\Providers" | ForEach-Object { Write-Output "$($_.PSChildName)" }'

Sec 'APPLOCKER'
try {
    $rules = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
    if ($rules) {
        Write-Output "[+] AppLocker policy is active"
        $rules.RuleCollections | ForEach-Object { Write-Output "  Collection: $($_.RuleCollectionType) — $($_.Count) rules" }
    } else {
        Write-Output "[*] No AppLocker policy"
    }
} catch {
    Write-Output "[*] AppLocker not available"
}

Sec 'CREDENTIAL_GUARD'
$cg = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root/Microsoft/Windows/DeviceGuard -ErrorAction SilentlyContinue)
if ($cg) {
    Write-Output "VBS: $($cg.VirtualizationBasedSecurityStatus)"
    Write-Output "CredentialGuard: $($cg.SecurityServicesRunning -contains 1)"
} else {
    Write-Output "[*] Device Guard info unavailable"
}

Sec 'EDR_PROCESSES'
$edrProcs = @("MsSense","SenseIR","SenseCncProxy","csvhost","cb","CbDefense","CylanceSvc",
    "falcon","CSFalconService","CSFalconContainer","taniumclient","SentinelAgent","SentinelOne",
    "elastic-agent","elastic-endpoint","winlogbeat","filebeat","splunkd","ossec-agent",
    "wazuh-agent","osqueryd","sysmon","Sysmon64","MsMpEng","NisSrv")
$running = Get-Process -ErrorAction SilentlyContinue | Where-Object { $edrProcs -contains $_.Name }
if ($running) {
    Write-Output "Running EDR/Security processes:"
    $running | Format-Table Name, Id, Path -AutoSize
} else {
    Write-Output "[*] No known EDR processes detected"
}

Sec 'SYSMON'
$sysmon = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
if ($sysmon) {
    Write-Output "[+] Sysmon is installed: $($sysmon.Status)"
    fltmc 2>$null | Select-String "SysmonDrv"
} else {
    Write-Output "[*] Sysmon not installed"
}

Sec 'WINDOWS_EVENT_FORWARDING'
$wef = wecutil es 2>$null
if ($wef) { Write-Output "[+] WEF subscriptions: $($wef.Count)" } else { Write-Output "[*] No WEF" }

Sec 'POWERSHELL_LOGGING'
$psLog = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
$psTranscript = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue
Write-Output "ScriptBlockLogging: $($psLog.EnableScriptBlockLogging)"
Write-Output "Transcription: $($psTranscript.EnableTranscripting)"
Write-Output "TranscriptionDir: $($psTranscript.OutputDirectory)"

Sec 'UAC_LEVEL'
$uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
Write-Output "EnableLUA: $($uac.EnableLUA)"
Write-Output "ConsentPromptBehaviorAdmin: $($uac.ConsentPromptBehaviorAdmin)"

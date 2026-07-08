# gather/windows/enum-kerberos-events.ps1 — Enumerate Kerberos ticket activity and weak encryption indicators
# Requires: Standard user
# Read-only: YES
# MITRE ATT&CK: T1558

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }

Sec 'OBJECTIVE'
'Collect Kerberos service ticket activity and highlight weak encryption types that may indicate insecure configuration or kerberoasting opportunities.'

Sec 'KERBEROS_SERVICE_TICKETS'
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 120 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message

Sec 'KERBEROS_WEAK_ENCRYPTION'
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 120 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Properties.Count -gt 5 -and ($_.Properties[5].Value -in @('0x17','0x18'))
    } | Select-Object TimeCreated, Id, Message

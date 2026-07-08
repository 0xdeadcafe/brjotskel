# gather/windows/enum-rasvpn-events.ps1 — Enumerate Microsoft Remote Access / RAS VPN events
# Requires: Standard user
# Read-only: YES
# MITRE ATT&CK: T1021 / remote access evidence

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }

Sec 'OBJECTIVE'
'Collect RemoteAccess / RAS VPN client and server events for successful logons, logoffs, connection establishment, and authentication failures.'

Sec 'RASVPN_SERVER_EVENTS'
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddDays(-14)} -MaxEvents 120 -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -eq 'RemoteAccess' -and $_.Id -in 20250,20271,20272,20274,20275 } |
    Select-Object TimeCreated, Id, ProviderName, Message

Sec 'RASVPN_CLIENT_EVENTS'
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddDays(-14)} -MaxEvents 120 -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -eq 'RemoteAccess' -and $_.Id -in 20220,20221,20222,20223,20224,20225,20226,20227,20253,20255 } |
    Select-Object TimeCreated, Id, ProviderName, Message

# gather/windows/enum-dnscache.ps1 — Enumerate Windows DNS client cache
# Requires: Standard user
# Read-only: YES
# MITRE ATT&CK: T1016 / T1049

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }

Sec 'OBJECTIVE'
'Collect recent DNS client cache entries to identify peer systems, C2 lookups, and unusual internal or external destinations.'

Sec 'DNS_CACHE'
Get-DnsClientCache | Select-Object Entry, RecordType, Data, TimeToLive, Status | Sort-Object Entry

Sec 'DNS_CACHE_SUSPICIOUS_HINTS'
Get-DnsClientCache | Where-Object {
    $_.Entry -match '^[a-z0-9.-]+$' -and (
        $_.Entry -match 'vpn|ssh|rdp|admin|auth|gateway|jump|dc|kdc|ldap|kerb|api|token|secret|corp|internal' -or
        $_.Entry -match '[0-9a-f]{8,}'
    )
} | Select-Object Entry, RecordType, Data, TimeToLive, Status | Sort-Object Entry

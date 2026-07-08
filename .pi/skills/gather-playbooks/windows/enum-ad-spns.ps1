# gather/windows/enum-ad-spns.ps1 — Enumerate SPN-bearing accounts and Kerberoastable targets
# Requires: Domain user
# Read-only: YES
# MITRE ATT&CK: T1558.003

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }

Sec 'OBJECTIVE'
'Collect SPN-bearing accounts and service principal names that may indicate service accounts, delegation, and Kerberoastable targets.'

Sec 'SPN_USERS'
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.Filter = '(&(objectCategory=user)(servicePrincipalName=*))'
@('samaccountname','serviceprincipalname','description','memberof') | ForEach-Object { [void]$searcher.PropertiesToLoad.Add($_) }
$searcher.PageSize = 500
$searcher.FindAll() | ForEach-Object {
    [pscustomobject]@{
        SamAccountName = $_.Properties['samaccountname'][0]
        Description = $_.Properties['description'][0]
        SPNs = ($_.Properties['serviceprincipalname']) -join '; '
    }
} | Sort-Object SamAccountName | Format-Table -Wrap -AutoSize

Sec 'COMPUTER_SPNS'
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.Filter = '(&(objectCategory=computer)(servicePrincipalName=*))'
@('dnshostname','serviceprincipalname') | ForEach-Object { [void]$searcher.PropertiesToLoad.Add($_) }
$searcher.PageSize = 300
$searcher.FindAll() | ForEach-Object {
    [pscustomobject]@{
        DnsHostName = $_.Properties['dnshostname'][0]
        SPNs = ($_.Properties['serviceprincipalname'] | Select-Object -First 6) -join '; '
    }
} | Sort-Object DnsHostName | Format-Table -Wrap -AutoSize

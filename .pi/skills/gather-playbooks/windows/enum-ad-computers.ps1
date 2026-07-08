# gather/windows/enum-ad-computers.ps1 — Enumerate domain computers and selected attributes
# Requires: Domain user
# Read-only: YES
# MITRE ATT&CK: T1018 / T1087.002

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }

Sec 'OBJECTIVE'
'Collect domain computer objects, host naming clues, operating system fields, and selected admin-related attributes.'

Sec 'DOMAIN_COMPUTERS'
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.Filter = '(&(objectCategory=computer)(objectClass=computer))'
@('dnshostname','name','operatingsystem','operatingsystemversion','description','managedby') | ForEach-Object { [void]$searcher.PropertiesToLoad.Add($_) }
$searcher.PageSize = 500
$searcher.FindAll() | ForEach-Object {
    [pscustomobject]@{
        Name = $_.Properties['name'][0]
        DnsHostName = $_.Properties['dnshostname'][0]
        OperatingSystem = $_.Properties['operatingsystem'][0]
        OperatingSystemVersion = $_.Properties['operatingsystemversion'][0]
        ManagedBy = $_.Properties['managedby'][0]
        Description = $_.Properties['description'][0]
    }
} | Sort-Object Name | Format-Table -Wrap -AutoSize

Sec 'COMPUTER_DISCOVERY_HINTS'
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.Filter = '(&(objectCategory=computer)(|(name=*dc*)(name=*sql*)(name=*db*)(name=*admin*)(name=*jump*)(name=*ws*)))'
@('name','dnshostname','operatingsystem') | ForEach-Object { [void]$searcher.PropertiesToLoad.Add($_) }
$searcher.PageSize = 200
$searcher.FindAll() | ForEach-Object {
    [pscustomobject]@{
        Name = $_.Properties['name'][0]
        DnsHostName = $_.Properties['dnshostname'][0]
        OperatingSystem = $_.Properties['operatingsystem'][0]
    }
} | Sort-Object Name | Format-Table -AutoSize

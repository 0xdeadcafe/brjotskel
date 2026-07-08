# gather/windows/enum-ad-users.ps1 — Enumerate AD users and high-signal account flags
# Requires: Domain user
# Read-only: YES
# MITRE ATT&CK: T1087.002

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }
function New-Searcher($filter, $props) {
    $s = New-Object DirectoryServices.DirectorySearcher
    $s.Filter = $filter
    foreach ($p in $props) { [void]$s.PropertiesToLoad.Add($p) }
    $s.PageSize = 500
    return $s
}

Sec 'OBJECTIVE'
'Collect AD user inventory and highlight disabled, locked, no-preauth, and service-linked user accounts.'

Sec 'AD_USERS'
$s = New-Searcher '(&(objectCategory=person)(objectClass=user))' @('samaccountname','userprincipalname','displayname','description','memberof','useraccountcontrol','mail')
$s.FindAll() | ForEach-Object {
    [pscustomobject]@{
        SamAccountName = $_.Properties['samaccountname'][0]
        UserPrincipalName = $_.Properties['userprincipalname'][0]
        DisplayName = $_.Properties['displayname'][0]
        Mail = $_.Properties['mail'][0]
        Description = $_.Properties['description'][0]
        UserAccountControl = $_.Properties['useraccountcontrol'][0]
    }
} | Sort-Object SamAccountName | Format-Table -AutoSize

Sec 'ASREP_ROASTABLE_USERS'
$s = New-Searcher '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' @('samaccountname','description')
$s.FindAll() | ForEach-Object {
    [pscustomobject]@{
        SamAccountName = $_.Properties['samaccountname'][0]
        Description = $_.Properties['description'][0]
    }
} | Format-Table -AutoSize

Sec 'SERVICE_LIKE_USERS'
$s = New-Searcher '(&(objectCategory=person)(objectClass=user)(|(samaccountname=*svc*)(description=*service*)))' @('samaccountname','description','memberof')
$s.FindAll() | ForEach-Object {
    [pscustomobject]@{
        SamAccountName = $_.Properties['samaccountname'][0]
        Description = $_.Properties['description'][0]
        Groups = ($_.Properties['memberof'] | Select-Object -First 3) -join '; '
    }
} | Format-Table -AutoSize

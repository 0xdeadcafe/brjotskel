# gather/windows/enum-ad-groups.ps1 — Enumerate privileged and interesting AD groups
# Requires: Domain user
# Read-only: YES
# MITRE ATT&CK: T1069.002

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }
function Show-NetGroup($name) {
    Write-Output "--- $name ---"
    net group "$name" /domain 2>$null | Select-String -NotMatch '^The command|^Group name|^Comment|^Members|^---|^The request' 
}

Sec 'OBJECTIVE'
'Collect privileged and operationally relevant AD groups and their members.'

Sec 'PRIVILEGED_GROUPS'
$groups = @(
    'Domain Admins','Enterprise Admins','Schema Admins','Administrators',
    'Account Operators','Backup Operators','Server Operators','DnsAdmins',
    'Group Policy Creator Owners','Remote Desktop Users'
)
foreach ($g in $groups) { Show-NetGroup $g }

Sec 'CURRENT_USER_DOMAIN_GROUPS'
whoami /groups 2>$null | Select-String 'Domain|BUILTIN|Mandatory'

Sec 'GROUP_DISCOVERY_HINTS'
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.Filter = '(&(objectCategory=group)(|(cn=*admin*)(cn=*remote*)(cn=*backup*)(cn=*vpn*)))'
@('cn','distinguishedname') | ForEach-Object { [void]$searcher.PropertiesToLoad.Add($_) }
$searcher.PageSize = 300
$searcher.FindAll() | ForEach-Object {
    [pscustomobject]@{
        Group = $_.Properties['cn'][0]
        DistinguishedName = $_.Properties['distinguishedname'][0]
    }
} | Sort-Object Group | Format-Table -AutoSize

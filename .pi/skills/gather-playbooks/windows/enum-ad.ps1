# gather/windows/enum-ad.ps1 — Active Directory enumeration
# Requires: Domain user (no special privileges needed for most queries)
# Read-only: YES
# MITRE ATT&CK: T1087.002 — Domain Account Discovery

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }
function Run($c) { Write-Output "PS> $c"; Invoke-Expression $c }

Sec 'DOMAIN_INFO'
try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    Write-Output "Domain: $($domain.Name)"
    Write-Output "Forest: $($domain.Forest.Name)"
    Write-Output "DCs: $($domain.DomainControllers | ForEach-Object { $_.Name })"
    Write-Output "DomainMode: $($domain.DomainMode)"
} catch {
    Write-Output "[-] Not domain-joined or cannot reach DC"
    Write-Output "[*] Computer domain: $env:USERDNSDOMAIN"
}

Sec 'TRUSTS'
Run 'nltest /domain_trusts'

Sec 'DOMAIN_CONTROLLERS'
Run 'nltest /dclist:$env:USERDNSDOMAIN'

Sec 'PRIVILEGED_GROUPS'
$groups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Account Operators",
    "Backup Operators", "DnsAdmins", "Server Operators")
foreach ($g in $groups) {
    $members = net group "$g" /domain 2>$null | Select-String -NotMatch "^The command|^Group name|^Comment|^Members|^---"
    if ($members) { Write-Output "--- $g ---"; Write-Output $members }
}

Sec 'CURRENT_USER_DOMAIN_GROUPS'
Run 'whoami /groups | Select-String "Domain\\|BUILTIN\\|Mandatory"'

Sec 'KERBEROS_TICKETS'
Run 'klist'

Sec 'SPNS_KERBEROASTABLE'
$searcher = New-Object DirectoryServices.DirectorySearcher -ErrorAction SilentlyContinue
if ($searcher) {
    $searcher.Filter = "(&(objectCategory=user)(servicePrincipalName=*))"
    $searcher.PropertiesToLoad.AddRange(@("samaccountname","serviceprincipalname","memberof"))
    try {
        $results = $searcher.FindAll()
        foreach ($r in $results) {
            $name = $r.Properties["samaccountname"][0]
            $spns = $r.Properties["serviceprincipalname"] -join ", "
            Write-Output "  $name : $spns"
        }
    } catch {}
}

Sec 'ASREP_ROASTABLE'
if ($searcher) {
    $searcher.Filter = "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
    $searcher.PropertiesToLoad.Clear()
    $searcher.PropertiesToLoad.Add("samaccountname") | Out-Null
    try {
        $results = $searcher.FindAll()
        foreach ($r in $results) { Write-Output "  $($r.Properties['samaccountname'][0])" }
    } catch {}
}

Sec 'DOMAIN_PASSWORD_POLICY'
Run 'net accounts /domain'

Sec 'RECENT_DOMAIN_LOGONS'
Run 'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4624; StartTime=(Get-Date).AddDays(-3)} -MaxEvents 20 | Where-Object { $_.Properties[8].Value -in @(2,3,10) } | ForEach-Object { $logonType = $_.Properties[8].Value; $user = "{0}\{1}" -f $_.Properties[6].Value, $_.Properties[5].Value; $src = $_.Properties[18].Value; Write-Output "  $($_.TimeCreated) | Type:$logonType | $user | From:$src" }'

Sec 'GPO_LIST'
Run 'gpresult /r | Select-String "Applied Group Policy|Filtering" | Select-Object -First 20'

Sec 'LAPS'
try {
    $root = [ADSI]"LDAP://RootDSE"
    $base = "LDAP://" + $root.defaultNamingContext
    $machineSearcher = New-Object DirectoryServices.DirectorySearcher([ADSI]$base)
    $machineSearcher.Filter = "(&(objectCategory=computer)(sAMAccountName=$env:COMPUTERNAME`$))"
    [void]$machineSearcher.PropertiesToLoad.Add("dnshostname")
    [void]$machineSearcher.PropertiesToLoad.Add("ms-Mcs-AdmPwd")
    $machine = $machineSearcher.FindOne()
    if ($machine -and $machine.Properties["ms-mcs-admpwd"] -and $machine.Properties["ms-mcs-admpwd"].Count -gt 0) {
        Write-Output "[+] LAPS password readable for $env:COMPUTERNAME : $($machine.Properties["ms-mcs-admpwd"][0])"
    } elseif ($machine) {
        Write-Output "[*] LAPS not readable, not configured, or access denied for this computer object"
    } else {
        Write-Output "[*] Computer object not found in directory search"
    }
} catch {
    Write-Output "[*] Cannot query LAPS via directory search"
}

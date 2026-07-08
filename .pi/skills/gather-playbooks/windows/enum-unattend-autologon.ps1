# gather/windows/enum-unattend-autologon.ps1 — Enumerate unattend, sysprep, and autologon plaintext credential sources
# Requires: Standard user (admin may improve access to some paths)
# Read-only: YES
# MITRE ATT&CK: T1552

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }

$unattendPaths = @(
    'C:\unattend.xml',
    'C:\Windows\Panther\unattend.xml',
    'C:\Windows\Panther\Unattend\unattend.xml',
    'C:\Windows\system32\sysprep\sysprep.xml',
    'C:\Windows\system32\sysprep\unattend.xml',
    'C:\Windows\Panther\Unattend\Unattend.xml'
)

Sec 'OBJECTIVE'
'Collect unattended setup files, sysprep artifacts, autologon registry values, and other nearby plaintext credential sources.'

Sec 'UNATTEND_AND_SYSPREP_PATHS'
foreach ($f in $unattendPaths) {
    if (Test-Path $f) {
        Get-Item $f | Select-Object FullName, Length, LastWriteTime
    }
}

Sec 'UNATTEND_AND_SYSPREP_CONTENT_HINTS'
foreach ($f in $unattendPaths) {
    if (Test-Path $f) {
        Write-Output "--- $f ---"
        Select-String -Path $f -Pattern 'Password|UserName|AdminPassword|Domain|Credentials|AutoLogon|RegisteredOwner|RegisteredOrganization' -Context 1,1
    }
}

Sec 'AUTOLOGON_REGISTRY'
$regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Get-ItemProperty $regPath -ErrorAction SilentlyContinue | Select-Object DefaultUserName, DefaultPassword, DefaultDomainName, AutoAdminLogon, AltDefaultUserName, AltDefaultDomainName

Sec 'LSA_AND_WINLOGON_HINTS'
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue | Select-Object LimitBlankPasswordUse, DisabledDomainCreds, EveryoneIncludesAnonymous
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue | Select-Object dontdisplaylastusername, legalnoticecaption, legalnoticetext

Sec 'UNATTEND_ADJACENT_FILES'
$adjacent = @(
    'C:\Windows\Panther',
    'C:\Windows\Panther\Unattend',
    'C:\Windows\system32\sysprep'
)
foreach ($d in $adjacent) {
    if (Test-Path $d) {
        Write-Output "--- $d ---"
        Get-ChildItem $d -Force -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime
    }
}

Sec 'RELATED_LOGON_ARTIFACTS'
Get-ChildItem 'C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' -Force -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime
Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | Select-Object Name, Command, User, Location

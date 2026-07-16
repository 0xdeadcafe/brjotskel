# escalate/windows/local-privesc-audit.ps1 — Assess Windows privilege-escalation paths
# Requires: Standard user (some checks benefit from admin)
# Read-only: YES
# MITRE ATT&CK: T1134 / T1574 / T1053 / T1547

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }

Sec 'OBJECTIVE'
'Assess Windows privilege-escalation paths using native commands: token privileges, services, installer policy, saved creds, writable paths, elevated tasks, and LOLBAS-style candidates.'

Sec 'CURRENT_CONTEXT'
whoami
whoami /all
whoami /priv

Sec 'TOKEN_ABUSE_INDICATORS'
whoami /priv | Select-String 'SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege|SeBackupPrivilege|SeRestorePrivilege|SeTakeOwnershipPrivilege|SeDebugPrivilege|SeLoadDriverPrivilege'

Sec 'ADMIN_EQUIVALENT_GROUPS'
whoami /groups | Select-String 'Administrators|Backup Operators|Server Operators|Print Operators|Hyper-V Administrators|Remote Management Users'

Sec 'ALWAYS_INSTALL_ELEVATED'
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

Sec 'AUTOLOGON_AND_SAVED_CREDS'
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
cmdkey /list
Get-ChildItem -Path C:\ -Include unattend.xml,unattended.xml,sysprep.xml -Recurse -Force -EA 0 | Select-Object -ExpandProperty FullName

Sec 'UAC_AND_POLICY'
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy

Sec 'SERVICES_UNQUOTED_PATHS'
Get-CimInstance Win32_Service |
  Where-Object { $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match '\s' } |
  Select-Object Name, StartName, State, StartMode, PathName

Sec 'SERVICES_WRITABLE_PATH_HINTS'
Get-CimInstance Win32_Service | ForEach-Object {
  $raw = $_.PathName
  if (-not $raw) { return }
  $exe = ($raw -replace '^"','' -replace '".*$','' -replace '\s+[-/].*$','').Trim()
  if (-not $exe) { return }
  $parent = Split-Path $exe -Parent
  if (Test-Path $parent) {
    try {
      $acl = Get-Acl $parent
      $weak = $acl.Access | Where-Object {
        $_.IdentityReference -match 'Everyone|BUILTIN\\Users|Authenticated Users' -and
        $_.FileSystemRights.ToString() -match 'Write|Modify|FullControl|CreateFiles|AppendData'
      }
      if ($weak) {
        [PSCustomObject]@{ Service = $_.Name; Parent = $parent; Identity = ($weak.IdentityReference -join ','); Rights = ($weak.FileSystemRights -join ',') }
      }
    } catch {}
  }
}

Sec 'HIGH_INTEGRITY_TASKS'
Get-ScheduledTask | Where-Object {
  $_.Principal.RunLevel -eq 'Highest' -or $_.Principal.UserId -match 'SYSTEM|Administrators'
} | Select-Object TaskPath, TaskName, State, @{n='User';e={$_.Principal.UserId}}, @{n='RunLevel';e={$_.Principal.RunLevel}}

Sec 'WRITABLE_PATH_ENTRIES'
$paths = @()
if ($env:Path) { $paths += ($env:Path -split ';') }
try {
  $machine = [Environment]::GetEnvironmentVariable('Path','Machine')
  if ($machine) { $paths += ($machine -split ';') }
} catch {}
$paths | Sort-Object -Unique | ForEach-Object {
  if ($_ -and (Test-Path $_)) {
    try {
      $acl = Get-Acl $_
      $weak = $acl.Access | Where-Object {
        $_.IdentityReference -match 'Everyone|BUILTIN\\Users|Authenticated Users' -and
        $_.FileSystemRights.ToString() -match 'Write|Modify|FullControl|CreateFiles|AppendData'
      }
      if ($weak) {
        [PSCustomObject]@{ Path = $_; Identity = ($weak.IdentityReference -join ','); Rights = ($weak.FileSystemRights -join ',') }
      }
    } catch {}
  }
}

Sec 'LOLBAS_CANDIDATES_PRESENT'
$bins = 'cmd.exe','powershell.exe','pwsh.exe','mshta.exe','regsvr32.exe','rundll32.exe','msiexec.exe','schtasks.exe','sc.exe','certutil.exe','cscript.exe','wscript.exe','forfiles.exe','bash.exe'
foreach ($b in $bins) {
  Get-Command $b -ErrorAction SilentlyContinue | Select-Object Name, Source
}

Sec 'SUSPICIOUS_MISCONFIGS'
'[!] High-signal findings: SeImpersonate/SeAssignPrimaryToken present on a service context, unquoted service paths, weak ACLs on service directories, AlwaysInstallElevated enabled in HKLM and HKCU, plaintext autologon values, writable PATH entries, and elevated tasks calling writable scripts.'

Sec 'EVIDENCE_TO_PRESERVE'
'[*] Preserve service names, exact ImagePath/PathName values, ACL output, task paths, registry keys, and any referenced script/batch/MSI paths before remediation or exploitation.'

Sec 'NEXT_ACTIONS'
'[*] If the operator wants command-level exploitation guidance, pivot to shell-commands and map validated findings to LOLBAS or native admin tooling with explicit state-change warnings.'

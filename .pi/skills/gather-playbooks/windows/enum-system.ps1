# gather/windows/enum-system.ps1 — System and user enumeration
# Requires: Standard user (admin for full coverage)
# Read-only: YES
# MITRE ATT&CK: T1082 — System Information Discovery

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }
function Run($c) { Write-Output "PS> $c"; Invoke-Expression $c }

Sec 'SYSTEM_INFO'
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
Write-Output "Hostname: $env:COMPUTERNAME"
Write-Output "Domain: $env:USERDOMAIN / $env:USERDNSDOMAIN"
Write-Output "OS: $($os.Caption) $($os.Version) Build $($os.BuildNumber)"
Write-Output "Arch: $env:PROCESSOR_ARCHITECTURE"
Write-Output "Boot: $($os.LastBootUpTime)"

Sec 'CURRENT_USER'
Run 'whoami /priv'
Run 'whoami /groups | Select-Object -First 20'

Sec 'LOCAL_USERS'
Run 'Get-LocalUser | Format-Table Name, Enabled, LastLogon, PasswordLastSet'

Sec 'LOCAL_GROUPS'
Run 'Get-LocalGroup | ForEach-Object { $members = Get-LocalGroupMember $_.Name -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }; if ($members) { Write-Output "$($_.Name): $($members -join \", \")" } }'

Sec 'LOGGED_ON_USERS'
Run 'query user'

Sec 'SERVICES_NON_MICROSOFT'
Run 'Get-CimInstance Win32_Service | Where-Object { $_.PathName -and $_.PathName -notmatch "Windows\\System32|Microsoft|svchost" } | Format-Table Name, State, StartMode, @{N="Path";E={$_.PathName}} -AutoSize | Out-String -Width 200'

Sec 'SCHEDULED_TASKS_NON_MICROSOFT'
Run 'Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch "\\Microsoft\\\\" -and $_.State -ne "Disabled" } | Format-Table TaskName, TaskPath, State -AutoSize'

Sec 'INSTALLED_SOFTWARE'
Run 'Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object { $_.DisplayName } | Sort-Object DisplayName | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize | Out-String -Width 200 | Select-Object -First 40'

Sec 'POWERSHELL_VERSION'
Run '$PSVersionTable | Format-Table -AutoSize'

Sec 'DOTNET_VERSIONS'
Run 'Get-ChildItem "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP" -Recurse | Get-ItemProperty -Name Version -ErrorAction SilentlyContinue | Select-Object PSChildName, Version | Format-Table'

Sec 'RECENT_INSTALLS'
Run 'Get-WinEvent -FilterHashtable @{LogName="Application"; ID=11707; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 10 | ForEach-Object { Write-Output "$($_.TimeCreated): $($_.Message)" }'

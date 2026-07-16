# host-ir/windows/persistence-hunt.ps1 — Hunt persistence mechanisms on a Windows host
# Requires: Admin for full coverage
# Read-only: YES
# MITRE ATT&CK: T1547 / T1053 / T1543 / T1546

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }
function Run($c) { Write-Output "PS> $c"; Invoke-Expression $c }

Sec 'OBJECTIVE'
'Windows persistence hunt: services, Run keys, scheduled tasks, WMI, startup folders, and remote-access clues.'

Sec 'HOST_CONTEXT'
Run 'hostname'
Run 'whoami'
Run 'Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, CSName, LastBootUpTime'

Sec 'SERVICES'
Run 'Get-CimInstance Win32_Service | Select-Object State, StartMode, Name, DisplayName, PathName | Sort-Object StartMode, Name'

Sec 'SCHEDULED_TASKS'
Run 'Get-ScheduledTask | Select-Object TaskPath, TaskName, State, Author, Description'
Run 'schtasks /query /fo LIST /v'

Sec 'RUN_KEYS'
Run 'reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Run 'reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Run 'reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Run 'reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Run 'reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'

Sec 'STARTUP_FOLDERS'
Run 'Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -Force'
Run 'Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -Force'

Sec 'WMI_PERSISTENCE'
Run 'Get-CimInstance -Namespace root/subscription -ClassName __EventFilter'
Run 'Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer'
Run 'Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer'
Run 'Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding'

Sec 'LOGON_AND_REMOTE_ACCESS'
Run 'query user'
Run 'Get-NetTCPConnection | Sort-Object State, LocalPort | Select-Object -First 200 State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess'
Run 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections'
Run 'Get-LocalGroupMember -Group Administrators'

Sec 'SUSPICIOUS_SIGNS'
'[!] Review non-Microsoft scheduled tasks, services launched from user-writable paths, Run keys pointing to temp or profile directories, WMI consumers executing scripts/command lines, and interactive sessions tied to admin-enabled remote access.'

Sec 'NEXT_ACTIONS'
'[*] If persistence is confirmed, preserve the exact task, service, registry, or WMI object details, record affected accounts and destination systems with intel_add, and follow with host containment planning only after evidence is captured.'

# host-ir/windows/initial-assessment.ps1 — Initial Windows host IR assessment
# Requires: Admin recommended
# Read-only: YES
# MITRE ATT&CK: T1082 / T1078 / T1547 / T1059.001

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }
function Run($c) { Write-Output "PS> $c"; Invoke-Expression $c }

Sec 'OBJECTIVE'
'Windows initial host IR assessment: host role, live activity, recent execution clues, persistence indicators, and security state.'

Sec 'HOST_CONTEXT'
Run 'hostname'
Run 'whoami'
Run 'Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, CSName, LastBootUpTime'
Run 'Get-CimInstance Win32_ComputerSystem | Select-Object Domain, Manufacturer, Model, TotalPhysicalMemory'

Sec 'LIVE_ACTIVITY'
Run 'query user'
Run 'Get-Process | Sort-Object CPU -Descending | Select-Object -First 40 Name, Id, CPU, Path'
Run 'Get-NetTCPConnection | Sort-Object State, LocalPort | Select-Object -First 200 State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess'
Run 'Get-CimInstance Win32_Service | Where-Object { $_.State -eq "Running" } | Select-Object Name, DisplayName, StartMode, PathName | Sort-Object Name'

Sec 'PERSISTENCE_CLUES'
Run 'Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch "\\Microsoft\\" } | Select-Object TaskPath, TaskName, State, Author'
Run 'reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Run 'reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Run 'Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, User, Location'

Sec 'RECENT_EXECUTION'
Run 'Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Tail 100'
Run 'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4624; StartTime=(Get-Date).AddDays(-2)} -MaxEvents 30 | ForEach-Object { "{0} | LogonType:{1} | User:{2}\{3} | Src:{4}" -f $_.TimeCreated, $_.Properties[8].Value, $_.Properties[6].Value, $_.Properties[5].Value, $_.Properties[18].Value }'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-PowerShell/Operational"; StartTime=(Get-Date).AddDays(-2)} -MaxEvents 40 | Select-Object TimeCreated, Id, LevelDisplayName, Message'

Sec 'PLAINTEXT_CREDENTIAL_SOURCES'
Run '$unattendPaths = @("C:\unattend.xml","C:\Windows\Panther\unattend.xml","C:\Windows\Panther\Unattend\unattend.xml","C:\Windows\system32\sysprep\sysprep.xml","C:\Windows\system32\sysprep\unattend.xml"); foreach ($f in $unattendPaths) { if (Test-Path $f) { Write-Output "--- $f ---"; Select-String -Path $f -Pattern "Password|UserName|AdminPassword|AutoLogon" } }'
Run 'Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue | Select-Object DefaultUserName, DefaultPassword, DefaultDomainName, AutoAdminLogon'

Sec 'SECURITY_STATE'
Run 'Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, IsTamperProtected, AntivirusSignatureVersion'
Run 'Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction'

Sec 'SUSPICIOUS_SIGNS'
'[!] Investigate unsigned or user-writable service paths, non-Microsoft scheduled tasks, unexpected Run keys, unusual high-CPU processes, suspicious PowerShell history, unattend/sysprep files containing usernames or passwords, autologon registry values with DefaultPassword set, and repeated network connections to rare remote addresses.'

Sec 'NEXT_ACTIONS'
'[*] If suspicious artifacts are confirmed, preserve the exact task/service/registry path, record affected accounts and remote peers with intel_add, and follow with the persistence-hunt playbook plus windows/enum-unattend-autologon.ps1 for deeper plaintext credential-source review.'

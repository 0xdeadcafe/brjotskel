# host-ir/windows/triage.ps1 — Windows host IR triage wrapper
# Requires: Admin recommended
# Read-only: YES
# MITRE ATT&CK: T1082 / T1078 / T1059.001 / T1547 / T1021

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }
function Run($c) { Write-Output "PS> $c"; Invoke-Expression $c }

Sec 'OBJECTIVE'
'Windows host IR triage wrapper: run a recommended first-pass sequence for host context, high-signal event review, and Sysmon-based hunting.'

Sec 'WHY_IT_MATTERS'
'Use this wrapper when you need a quick but structured first pass on a suspicious Windows host before deeper persistence or PowerShell-specific reconstruction.'

Sec 'STEP_1_HOST_CONTEXT_AND_LIVE_ACTIVITY'
Run 'hostname'
Run 'whoami'
Run 'Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, CSName, LastBootUpTime'
Run 'query user'
Run 'Get-Process | Sort-Object CPU -Descending | Select-Object -First 30 Name, Id, CPU, Path'
Run 'Get-NetTCPConnection | Sort-Object State, LocalPort | Select-Object -First 120 State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess'
Run 'Get-DnsClientCache | Select-Object -First 80 Entry, RecordType, Data, TimeToLive'

Sec 'STEP_2_HIGH_SIGNAL_WINDOWS_EVENTS'
Run 'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4624; StartTime=(Get-Date).AddDays(-2)} -MaxEvents 20 | ForEach-Object { "{0} | 4624 | Type:{1} | Tgt:{2}\{3} | Src:{4}" -f $_.TimeCreated, $_.Properties[8].Value, $_.Properties[6].Value, $_.Properties[5].Value, $_.Properties[18].Value }'
Run 'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4625; StartTime=(Get-Date).AddDays(-2)} -MaxEvents 20 | ForEach-Object { "{0} | 4625 | Tgt:{1}\{2} | Src:{3}" -f $_.TimeCreated, $_.Properties[6].Value, $_.Properties[5].Value, $_.Properties[19].Value }'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-PowerShell/Operational"; ID=4104; StartTime=(Get-Date).AddDays(-2)} -MaxEvents 20 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="System"; ID=7045; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 20 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-TaskScheduler/Operational"; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 20 | Where-Object { $_.Id -in 106,140,141,200,201 } | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=1102; StartTime=(Get-Date).AddDays(-14)} -MaxEvents 10 | Select-Object TimeCreated, Id, Message'

Sec 'STEP_3_OPERATOR_AND_DEFENSE_ARTIFACTS'
Run 'Get-ChildItem "C:\Users" -Directory -Force | ForEach-Object { $hist = Join-Path $_.FullName "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"; if (Test-Path $hist) { Write-Output "--- $($_.Name) ---"; Get-Content $hist -Tail 20 } }'
Run '$base = "HKCU:\Software\SimonTatham\PuTTY\Sessions"; if (Test-Path $base) { Get-ChildItem $base | ForEach-Object { $p = Get-ItemProperty $_.PSPath; [pscustomobject]@{ Name=[uri]::UnescapeDataString($_.PSChildName); HostName=$p.HostName; UserName=$p.UserName; PortNumber=$p.PortNumber; PublicKeyFile=$p.PublicKeyFile } } | Format-Table -AutoSize }'
Run 'Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" -ErrorAction SilentlyContinue | Select-Object *'
Run 'Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes" -ErrorAction SilentlyContinue | Select-Object *'
Run 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" -ErrorAction SilentlyContinue | Select-Object FriendlyName, Mfg, Service, ContainerID'

Sec 'STEP_4_SYSMON_IF_PRESENT'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=1; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 40 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=3; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 30 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=10; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 25 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=19; StartTime=(Get-Date).AddDays(-14)} -MaxEvents 20 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=20; StartTime=(Get-Date).AddDays(-14)} -MaxEvents 20 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=21; StartTime=(Get-Date).AddDays(-14)} -MaxEvents 20 | Select-Object TimeCreated, Id, Message'

Sec 'SUSPICIOUS_SIGNS'
'[!] Prioritize unusual 4624 Type 3/10 logons, repeated 4625 failures, 4104 script blocks, 7045 service installs, Task Scheduler changes, 1102 log clearing, suspicious PSReadLine commands, PuTTY sessions pointing to rare internal hosts or key files, Defender exclusions for temp/profile/appdata paths, unexpected USB storage artifacts, anomalous DNS cache entries, Sysmon 1 execution from temp/profile paths, Sysmon 3 rare outbound connections, Sysmon 10 process access to high-value targets, and Sysmon 19/20/21 WMI persistence chains.'

Sec 'NEXT_ACTIONS'
'[*] If the host looks suspicious, follow with windows/eventlog-hunt.ps1 for deeper channel review, windows/sysmon-hunt.ps1 for richer Sysmon analysis, windows/powershell-reconstruction.ps1 for script reconstruction, windows/persistence-hunt.ps1 for startup persistence details, and the gather playbooks windows/psreadline-history.ps1, windows/putty-sessions.ps1, windows/enum-av-exclusions.ps1, windows/enum-dnscache.ps1, windows/enum-usb-history.ps1, windows/enum-artifacts.ps1, windows/enum-browser-artifacts.ps1, and windows/enum-prefetch.ps1 for fuller artifact and execution collection. Record confirmed users, source IPs, services, tasks, WMI objects, key-file paths, saved endpoints, and peer hosts with intel_add.'

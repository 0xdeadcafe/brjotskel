# host-ir/windows/eventlog-hunt-lite.ps1 — Quick high-signal Windows event-log review
# Requires: Standard user (admin improves Security log access)
# Read-only: YES
# MITRE ATT&CK: T1078 / T1059.001 / T1543.003 / T1053 / T1021

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }
function Run($c) { Write-Output "PS> $c"; Invoke-Expression $c }

Sec 'OBJECTIVE'
'Windows event-log hunt lite: quick, high-signal review of logons, PowerShell, service installs, task changes, WMI, RDP, Defender tampering, and log clearing.'

Sec 'WHY_IT_MATTERS'
'Use a fast first pass to identify whether deeper host event reconstruction is warranted before running the fuller eventlog-hunt playbook.'

Sec 'HIGH_SIGNAL_EVENTS'
Run 'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4624; StartTime=(Get-Date).AddDays(-2)} -MaxEvents 25 | ForEach-Object { "{0} | 4624 | Type:{1} | Tgt:{2}\{3} | Src:{4}" -f $_.TimeCreated, $_.Properties[8].Value, $_.Properties[6].Value, $_.Properties[5].Value, $_.Properties[18].Value }'
Run 'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4625; StartTime=(Get-Date).AddDays(-2)} -MaxEvents 25 | ForEach-Object { "{0} | 4625 | Tgt:{1}\{2} | Src:{3}" -f $_.TimeCreated, $_.Properties[6].Value, $_.Properties[5].Value, $_.Properties[19].Value }'
Run 'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4625; StartTime=(Get-Date).AddDays(-2)} -MaxEvents 200 | Group-Object { $_.Properties[5].Value } | Sort-Object Count -Descending | Select-Object -First 15 Count, Name'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-PowerShell/Operational"; ID=4104; StartTime=(Get-Date).AddDays(-2)} -MaxEvents 20 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="System"; ID=7045; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 30 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="System"; ID=7045; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 50 | Where-Object { $_.Message -match "PSEXESVC|cmd.exe /c|cmd /c|\\Users\\Public\\|\\Windows\\Temp\\|\\AppData\\|\\Perflogs\\|\\Downloads\\" } | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="System"; ID=7040; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 20 | Where-Object { $_.Message -match "Remote Registry" } | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-TaskScheduler/Operational"; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 25 | Where-Object { $_.Id -in 106,140,141,200,201 } | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-WMI-Activity/Operational"; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 20 | Where-Object { $_.Id -in 5860,5861 } | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"; ID=1149; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 20 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 40 | Where-Object { $_.Id -in 21,22,23,24,25,39 } | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="System"; StartTime=(Get-Date).AddDays(-14)} -MaxEvents 60 | Where-Object { $_.ProviderName -eq "RemoteAccess" -and $_.Id -in 20250,20271,20272,20274,20275,20221,20222,20223,20224,20225,20226,20227 } | Select-Object TimeCreated, Id, ProviderName, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4769; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 40 | Where-Object { $_.Message -match "0x17|0x18" } | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 40 -ErrorAction SilentlyContinue | Where-Object { $_.Id -in 8002,8004 -and $_.Message -match "powershell|cmd.exe|rundll32|regsvr32|mshta|wmic|certutil|bitsadmin" } | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Windows Defender/Operational"; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 20 | Where-Object { $_.Id -in 1116,5007 } | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=1102; StartTime=(Get-Date).AddDays(-14)} -MaxEvents 10 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="System"; ID=104; StartTime=(Get-Date).AddDays(-14)} -MaxEvents 10 | Select-Object TimeCreated, Id, Message'

Sec 'SUSPICIOUS_SIGNS'
'[!] Prioritize 4624 Type 3 or 10 logons from unusual IPs, grouped 4625 failures against the same user, 4104 script blocks, 7045 installs for PSEXESVC or cmd.exe /c services, service image paths in Public/Temp/AppData/Perflogs, 7040 Remote Registry changes, TaskScheduler 106/140/141 changes, WMI 5861 permanent bindings, RDP 1149 plus 21/22/23/39 session lifecycle bursts, RemoteAccess 20250/20274 VPN activity, Kerberos 4769 weak encryption use, AppLocker LOLBIN events, Defender 5007 tampering, and 1102/104 log clearing.'

Sec 'NEXT_ACTIONS'
'[*] If any of these events look suspicious, run windows/eventlog-hunt.ps1 for deeper reconstruction and record users, source IPs, service names, task names, Remote Registry state changes, VPN events, RDP session activity, and channels with intel_add. Use windows/enum-rasvpn-events.ps1, windows/enum-kerberos-events.ps1, and windows/enum-applocker-events.ps1 for deeper event-specific collection if needed.'

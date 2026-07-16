# host-ir/windows/eventlog-hunt.ps1 — Deep Windows event-log investigation
# Requires: Admin for full Security/Sysmon access
# Read-only: YES
# MITRE ATT&CK: T1078 / T1059.001 / T1543.003 / T1053 / T1021 / T1562

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }
function Run($c) { Write-Output "PS> $c"; Invoke-Expression $c }

Sec 'OBJECTIVE'
'Windows event-log hunt: investigate logon activity, service/task creation, PowerShell execution, WMI, RDP, log clearing, Defender, and Sysmon artifacts on a single host.'

Sec 'WHY_IT_MATTERS'
'Use Windows event channels to reconstruct what ran, who logged on, what changed, and whether the host shows signs of persistence, lateral movement, defense evasion, or anti-forensics.'

Sec 'LOGON_ACTIVITY'
Run 'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4624; StartTime=(Get-Date).AddDays(-3)} -MaxEvents 80 | ForEach-Object { "{0} | 4624 | Type:{1} | Tgt:{2}\{3} | SrcComp:{4} | SrcIP:{5} | LID:{6}" -f $_.TimeCreated, $_.Properties[8].Value, $_.Properties[6].Value, $_.Properties[5].Value, $_.Properties[11].Value, $_.Properties[18].Value, $_.Properties[7].Value }'
Run 'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4625; StartTime=(Get-Date).AddDays(-3)} -MaxEvents 120 | ForEach-Object { "{0} | 4625 | Type:{1} | Tgt:{2}\{3} | SrcComp:{4} | SrcIP:{5} | AuthPkg:{6} | Proc:{7}" -f $_.TimeCreated, $_.Properties[10].Value, $_.Properties[6].Value, $_.Properties[5].Value, $_.Properties[13].Value, $_.Properties[19].Value, $_.Properties[14].Value, $_.Properties[18].Value }'
Run 'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4625; StartTime=(Get-Date).AddDays(-3)} -MaxEvents 400 | Group-Object { "{0}|{1}" -f $_.Properties[5].Value, $_.Properties[19].Value } | Sort-Object Count -Descending | Select-Object -First 20 Count, Name'
Run 'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4648; StartTime=(Get-Date).AddDays(-3)} -MaxEvents 40 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4672; StartTime=(Get-Date).AddDays(-3)} -MaxEvents 40 | Select-Object TimeCreated, Id, Message'

Sec 'PROCESS_AND_SCRIPT_EXECUTION'
Run 'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4688; StartTime=(Get-Date).AddDays(-3)} -MaxEvents 80 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Windows PowerShell"; ID=400; StartTime=(Get-Date).AddDays(-3)} -MaxEvents 30 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-PowerShell/Operational"; ID=4103; StartTime=(Get-Date).AddDays(-3)} -MaxEvents 40 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-PowerShell/Operational"; ID=4104; StartTime=(Get-Date).AddDays(-3)} -MaxEvents 60 | Select-Object TimeCreated, Id, Message'

Sec 'SERVICE_AND_TASK_CHANGES'
Run 'Get-WinEvent -FilterHashtable @{LogName="System"; ID=7045; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 60 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="System"; ID=7045; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 120 | Where-Object { $_.Message -match "PSEXESVC|smbexec|csexec|krbrelayup|processhacker|procdump|rclone|anydesk|teamviewer|cmd.exe /c|cmd /c|\\Users\\Public\\|\\Windows\\Temp\\|\\AppData\\|\\Perflogs\\|\\Downloads\\" } | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="System"; ID=7040; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 40 | Where-Object { $_.Message -match "Remote Registry" } | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-TaskScheduler/Operational"; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 80 | Where-Object { $_.Id -in 106,140,141,200,201 } | Select-Object TimeCreated, Id, Message'

Sec 'WMI_AND_REMOTE_ACTIVITY'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-WMI-Activity/Operational"; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 80 | Where-Object { $_.Id -in 5857,5858,5859,5860,5861 } | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 40 | Where-Object { $_.Id -in 1149 } | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 80 | Where-Object { $_.Id -in 21,22,23,24,25,39 } | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="System"; StartTime=(Get-Date).AddDays(-14)} -MaxEvents 120 | Where-Object { $_.ProviderName -eq "RemoteAccess" -and $_.Id -in 20220,20221,20222,20223,20224,20225,20226,20227,20250,20253,20255,20271,20272,20274,20275 } | Select-Object TimeCreated, Id, ProviderName, Message'

Sec 'KERBEROS_APPLOCKER_DEFENDER_AND_TAMPERING'
Run 'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4769; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 100 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4769; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 100 | Where-Object { $_.Message -match "0x17|0x18" } | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 80 -ErrorAction SilentlyContinue | Where-Object { $_.Id -in 8002,8004 } | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -LogName "Microsoft-Windows-AppLocker/MSI and Script" -MaxEvents 80 -ErrorAction SilentlyContinue | Where-Object { $_.Id -in 8005,8007 } | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Windows Defender/Operational"; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 80 | Where-Object { $_.Id -in 1116,1117,5001,5007 } | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=1102; StartTime=(Get-Date).AddDays(-14)} -MaxEvents 20 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="System"; ID=104; StartTime=(Get-Date).AddDays(-14)} -MaxEvents 20 | Select-Object TimeCreated, Id, Message'

Sec 'SYSMON_IF_PRESENT'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 120 | Where-Object { $_.Id -in 1,3,7,8,11,12,13,22 } | Select-Object TimeCreated, Id, Message'

Sec 'SUSPICIOUS_SIGNS'
'[!] Prioritize 4624 Type 3 (network), 8 (network cleartext), 9 (new credentials), and 10 (remote interactive) logons from unusual sources; grouped 4625 failures by user/source; 4648 explicit credential use; 4672 special privileges; 7045 installs for PSEXESVC, smbexec-like names, cmd.exe /c services, or paths under Public/Temp/AppData/Perflogs; 7040 Remote Registry changes; TaskScheduler operational changes including creation and deletion; 4104 script blocks; WMI 5861 consumers; RDP 1149 plus 21/22/23/39 session bursts; RemoteAccess 20250/20274 VPN activity; 4769 weak Kerberos encryption usage; AppLocker LOLBIN events; Defender 5007 tampering; Security 1102/System 104 log clearing; and Sysmon 2 timestomping or Sysmon 19/20/21 WMI persistence chains when available.'

Sec 'NEXT_ACTIONS'
'[*] Correlate users, source IPs, service names, suspicious image paths, scheduled task names, VPN events, RDP session lifecycle events, Kerberos service names, script blocks, and WMI consumer details. Record confirmed hosts/accounts/pivots with intel_add, preserve key event messages and timestamps, and pivot to persistence-hunt, initial-assessment, or the focused gather playbooks windows/enum-rasvpn-events.ps1, windows/enum-kerberos-events.ps1, and windows/enum-applocker-events.ps1 for fuller reconstruction.'

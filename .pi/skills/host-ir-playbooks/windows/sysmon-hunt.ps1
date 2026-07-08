$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }
function Run($c) { Write-Output "PS> $c"; Invoke-Expression $c }

Sec 'OBJECTIVE'
'Sysmon-focused host hunt: process execution, network connections, timestomping, process access/injection, persistence-related registry/file events, WMI, DNS, and tampering.'

Sec 'WHY_IT_MATTERS'
'Sysmon provides higher-fidelity host telemetry than many default Windows logs. Use it to reconstruct attacker execution chains, persistence changes, injection/access behavior, and network activity.'

Sec 'PROCESS_EXECUTION'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=1; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 120 | Select-Object TimeCreated, Id, Message'

Sec 'NETWORK_AND_DNS'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=3; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 80 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=22; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 80 | Select-Object TimeCreated, Id, Message'

Sec 'FILE_AND_REGISTRY'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=2; StartTime=(Get-Date).AddDays(-14)} -MaxEvents 40 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=11; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 60 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=12; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 60 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=13; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 60 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=15; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 40 | Select-Object TimeCreated, Id, Message'

Sec 'PROCESS_ACCESS_AND_INJECTION'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=8; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 40 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=10; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 60 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=25; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 30 | Select-Object TimeCreated, Id, Message'

Sec 'WMI_AND_NAMED_PIPES'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=17; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 40 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=18; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 40 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=19; StartTime=(Get-Date).AddDays(-14)} -MaxEvents 30 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=20; StartTime=(Get-Date).AddDays(-14)} -MaxEvents 30 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=21; StartTime=(Get-Date).AddDays(-14)} -MaxEvents 30 | Select-Object TimeCreated, Id, Message'

Sec 'TAMPERING_AND_DELETION'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=16; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 20 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=23; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 30 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=26; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 30 | Select-Object TimeCreated, Id, Message'

Sec 'SUSPICIOUS_SIGNS'
'[!] Prioritize Sysmon 1 executions from temp/profile paths or LOLBAS-style parents, Sysmon 2 timestomping, Sysmon 3 rare outbound connections, Sysmon 8/10 injection or LSASS access, Sysmon 12/13 autorun or policy registry changes, Sysmon 15 ADS creation, Sysmon 19/20/21 WMI persistence chains, Sysmon 22 suspicious DNS, and Sysmon 16 config changes.'

Sec 'NEXT_ACTIONS'
'[*] Correlate Sysmon ProcessGuid/Image/ParentImage/CommandLine with Security 4624/4688 and PowerShell 4104 findings. Record confirmed accounts, source IPs, services, WMI objects, DNS destinations, and pivot hosts with intel_add.'

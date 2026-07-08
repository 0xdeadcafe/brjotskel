$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }
function Run($c) { Write-Output "PS> $c"; Invoke-Expression $c }

Sec 'OBJECTIVE'
'Reconstruct PowerShell activity on a single Windows host using classic and operational event logs, focusing on script block logging, pipeline execution, engine starts, and execution policy tampering.'

Sec 'WHY_IT_MATTERS'
'Hayabusa highlights 4103 and 4104 as key reconstruction sources. Script blocks are often fragmented across multiple events, and timeline context is critical for understanding what commands actually ran.'

Sec 'POWERSHELL_OPERATIONAL'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-PowerShell/Operational"; ID=4103; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 60 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-PowerShell/Operational"; ID=4104; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 80 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-PowerShell/Operational"; ID=4105; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 40 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-PowerShell/Operational"; ID=4106; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 40 | Select-Object TimeCreated, Id, Message'

Sec 'POWERSHELL_CLASSIC'
Run 'Get-WinEvent -FilterHashtable @{LogName="Windows PowerShell"; ID=400; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 40 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Windows PowerShell"; ID=403; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 40 | Select-Object TimeCreated, Id, Message'
Run 'Get-WinEvent -FilterHashtable @{LogName="Windows PowerShell"; ID=600; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 30 | Select-Object TimeCreated, Id, Message'

Sec 'SCRIPTBLOCK_FOCUS'
Run 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-PowerShell/Operational"; ID=4104; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 80 | Where-Object { $_.Message -match "Invoke-Expression|IEX|FromBase64String|EncodedCommand|-enc |DownloadString|Net.WebClient|Invoke-WebRequest|Start-BitsTransfer|Reflection.Assembly|Amsi|Add-MpPreference|Set-MpPreference" } | Select-Object TimeCreated, Id, Message'

Sec 'EXECUTION_POLICY_AND_DEFENSE_EVASION'
Run 'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4688; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 80 | Where-Object { $_.Message -match "powershell|pwsh|executionpolicy|bypass|encodedcommand|-enc" } | Select-Object TimeCreated, Id, Message'
Run 'reg query HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell /v ExecutionPolicy'
Run 'reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell /s'

Sec 'HISTORY_AND_CONSOLE'
Run 'Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Tail 150'

Sec 'SUSPICIOUS_SIGNS'
'[!] Prioritize 4104 script blocks containing encoded commands, download cradle patterns, reflection, AMSI bypass, Defender tampering, and execution policy bypass. Also review classic 400 engine-start events for full HostApplication command lines and 4688 process creation for powershell.exe or pwsh.exe with suspicious arguments.'

Sec 'NEXT_ACTIONS'
'[*] Preserve suspicious script block messages and timestamps, correlate them with logons, network connections, and service/task events, and record impacted users/hosts with intel_add. If output is fragmented or voluminous, export the relevant 4104/4103 records for offline reconstruction and timeline correlation.'

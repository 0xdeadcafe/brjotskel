# gather/windows/enum-applocker-events.ps1 — Enumerate AppLocker allow/block events and LOLBIN hints
# Requires: Standard user
# Read-only: YES
# MITRE ATT&CK: T1218 / execution control evidence

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }

Sec 'OBJECTIVE'
'Collect AppLocker allow/block events for executables, DLLs, MSI, and scripts, with emphasis on LOLBIN and reconnaissance patterns.'

Sec 'APPLOCKER_EXE_DLL'
Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL' -MaxEvents 120 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in 8002,8003,8004 } |
    Select-Object TimeCreated, Id, Message

Sec 'APPLOCKER_MSI_SCRIPT'
Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/MSI and Script' -MaxEvents 120 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in 8005,8006,8007 } |
    Select-Object TimeCreated, Id, Message

Sec 'APPLOCKER_LOLBIN_HINTS'
Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL' -MaxEvents 150 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Message -match 'powershell|cmd.exe|rundll32|regsvr32|mshta|wmic|certutil|bitsadmin|psexec|wscript|cscript'
    } | Select-Object TimeCreated, Id, Message

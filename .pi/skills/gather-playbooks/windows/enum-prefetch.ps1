# gather/windows/enum-prefetch.ps1 — Enumerate Prefetch execution artifacts
# Requires: Standard user (admin may improve coverage)
# Read-only: YES
# MITRE ATT&CK: T1204 / execution evidence

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }

Sec 'OBJECTIVE'
'Collect Prefetch execution artifacts to identify recently executed binaries, staging paths, and suspicious tool usage.'

Sec 'PREFETCH_FILES'
Get-ChildItem 'C:\Windows\Prefetch\*.pf' -Force | Select-Object Name, Length, LastWriteTime | Sort-Object LastWriteTime -Descending

Sec 'PREFETCH_SUSPICIOUS_NAMES'
Get-ChildItem 'C:\Windows\Prefetch\*.pf' -Force | Where-Object {
    $_.Name -match 'POWERSHELL|CMD|WSCRIPT|CSCRIPT|RUNDLL32|REGSVR32|MSHTA|BITSADMIN|CERTUTIL|PSEXEC|PLINK|CHISEL|NGROK|PUTTY|WINSCP|SCP|SSH|NET|WMIC|RCLONE|TEAMVIEWER|ANYDESK|MIMIKATZ|PROCDUMP'
} | Select-Object Name, Length, LastWriteTime | Sort-Object LastWriteTime -Descending

Sec 'PREFETCH_SUSPICIOUS_PATH_HINTS'
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
    $_.PathName -and $_.PathName -match 'Temp|AppData|ProgramData|Users\\Public'
} | Select-Object Name, State, StartMode, PathName

Sec 'APPCOMPAT_RECENT_EXECUTION_HINTS'
Get-ChildItem 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store' -ErrorAction SilentlyContinue | ForEach-Object {
    Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue | Select-Object *
}
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' -ErrorAction SilentlyContinue | Select-Object *

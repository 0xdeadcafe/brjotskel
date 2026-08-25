# host-ir-playbooks/windows/integrity-check.ps1 — Binary integrity verification
# Requires: Admin for full coverage
# Read-only: YES
# Purpose: Verify system binary integrity before trusting command output
#          on a host where DLL hijack or binary replacement is suspected.
#
# MITRE ATT&CK: T1574 (Hijack Execution Flow), T1036 (Masquerading)
#
# Run inline: remote_exec(session="host01", command="<paste>")

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }
function Warn($m) { Write-Output "[!] $m" }

Sec 'INTEGRITY CHECK HEADER'
Write-Output "Host:      $env:COMPUTERNAME"
Write-Output "Timestamp: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"

Sec 'RUNNING PROCESS AUTHENTICODE SIGNATURES'
Write-Output "Checking all running process binaries for valid signatures..."
$unsigned = @()
Get-Process | ForEach-Object {
  $path = $_.Path
  if (-not $path -or -not (Test-Path $path -PathType Leaf)) { return }
  $sig = Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue
  if ($sig -and $sig.Status -ne 'Valid') {
    $line = "[$($sig.Status)] PID=$($_.Id) $($_.ProcessName)  $path"
    Write-Output $line
    $unsigned += $line
  }
} 
if ($unsigned.Count -eq 0) { Write-Output "(all running process binaries are validly signed)" }

Sec 'UNSIGNED BINARIES IN SYSTEM DIRECTORIES'
Write-Output "Scanning System32 and SysWOW64 for unsigned binaries..."
$sysPaths = @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64")
foreach ($sp in $sysPaths) {
  Get-ChildItem $sp -Filter "*.exe" -File -Recurse -Depth 1 -ErrorAction SilentlyContinue | ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
    if ($sig -and $sig.Status -ne 'Valid') {
      Warn "Unsigned/invalid in $($sp): $($_.Name) [$($sig.Status)]"
      "  $(($sig.SignerCertificate?.Subject ?? '(no cert)'))"
    }
  }
}

Sec 'SERVICE BINARY INTEGRITY'
Write-Output "Checking service binaries for valid signatures..."
Get-CimInstance Win32_Service | ForEach-Object {
  $rawPath = $_.PathName
  if (-not $rawPath) { return }
  # Extract the executable from the service path (may have args)
  $binPath = ($rawPath -replace '"', '' -replace ' .*', '').Trim()
  if (-not (Test-Path $binPath -PathType Leaf)) { return }
  $sig = Get-AuthenticodeSignature $binPath -ErrorAction SilentlyContinue
  if ($sig -and $sig.Status -ne 'Valid') {
    Warn "Service '$($_.Name)': unsigned/invalid binary: $binPath [$($sig.Status)]"
  }
}

Sec 'DLL HIJACK — WRITABLE SERVICE BINARY DIRECTORIES'
Write-Output "Checking for writable directories in service binary paths..."
Get-CimInstance Win32_Service | ForEach-Object {
  $rawPath = $_.PathName
  if (-not $rawPath) { return }
  $binPath = ($rawPath -replace '"', '' -replace ' .*', '').Trim()
  $dir = [System.IO.Path]::GetDirectoryName($binPath)
  if (-not $dir -or -not (Test-Path $dir)) { return }
  try {
    $acl = Get-Acl $dir -ErrorAction Stop
    $writable = $acl.Access | Where-Object {
      $_.IdentityReference -match 'Everyone|Users|Authenticated Users|BUILTIN\\Users' -and
      $_.FileSystemRights -match 'Write|FullControl|Modify'
    }
    if ($writable) {
      Warn "Writable service directory '$dir' for service '$($_.Name)'"
      $writable | ForEach-Object { Write-Output "  $($_.IdentityReference): $($_.FileSystemRights)" }
    }
  } catch {}
}

Sec 'DLL SEARCH ORDER — SCHEDULED TASK BINARIES'
Get-ScheduledTask 2>$null |
  Where-Object { $_.TaskPath -notmatch '\\Microsoft\\' } |
  ForEach-Object {
    $_.Actions | ForEach-Object {
      $bin = $_.Execute -replace '"', '' -replace ' .*', ''
      if ($bin -and (Test-Path $bin -PathType Leaf)) {
        $dir = [System.IO.Path]::GetDirectoryName($bin)
        # Check if the directory is writable by non-admin
        try {
          $acl = Get-Acl $dir -ErrorAction Stop
          $writable = $acl.Access | Where-Object {
            $_.IdentityReference -match 'Everyone|BUILTIN\\Users' -and
            $_.FileSystemRights -match 'Write|FullControl'
          }
          if ($writable) {
            Warn "Scheduled task writable dir: $dir  (task: $($_.TaskName ?? 'unknown'))"
          }
        } catch {}
      }
    }
  }

Sec 'KEY BINARY HASH SPOT-CHECK'
Write-Output "Hashes for key triage tools (verify against known-good baseline):"
$keyBins = @(
  "$env:SystemRoot\System32\cmd.exe",
  "$env:SystemRoot\System32\powershell.exe",
  "$env:SystemRoot\System32\net.exe",
  "$env:SystemRoot\System32\sc.exe",
  "$env:SystemRoot\System32\schtasks.exe",
  "$env:SystemRoot\System32\tasklist.exe",
  "$env:SystemRoot\System32\netstat.exe"
)
foreach ($b in $keyBins) {
  if (Test-Path $b) {
    $h = (Get-FileHash $b -Algorithm SHA256 -EA SilentlyContinue).Hash
    Write-Output "  $h  $b"
  }
}

Sec 'INTEGRITY CHECK COMPLETE'
Write-Output "If unsigned/tampered binaries were found:"
Write-Output "  1. Cross-reference hashes against Microsoft baseline (winbindex.daniellussier.com)"
Write-Output "  2. Do not trust output from tampered binaries"
Write-Output "  3. Use WMI/COM queries instead of CLI tools for process/network state"
Write-Output "  4. Record with intel_update(category='host', ...)"

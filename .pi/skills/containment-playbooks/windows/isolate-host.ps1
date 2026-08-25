# containment/windows/isolate-host.ps1 — Network isolation (nuclear option) on Windows
# Requires: Admin / SYSTEM
# State-changing: YES — modifies Windows Firewall profile rules; host loses all network except analyst
# Pattern: EVIDENCE → LOCK IN ANALYST → BLOCK EVERYTHING → VERIFY
#
# Parameters:
#   $AnalystIp   — your IP address (REQUIRED — get this wrong and you're locked out)
#   $KeepPort    — port to keep open for analyst: 5985 (WinRM, default) or 22 (SSH)
#
# Usage:
#   $AnalystIp = "10.10.0.5"; <paste>
#   $AnalystIp = "10.10.0.5"; $KeepPort = 22; <paste>
#
# ⚠️  VERIFY $AnalystIp BEFORE RUNNING — wrong IP = locked out, requires console/OOB access
# ⚠️  Run collect-evidence.ps1 FIRST — isolation kills all non-analyst connections
# ⚠️  Coordinate with incident commander — other hosts on the same network may be affected
# ⚠️  Windows Firewall rules PERSIST ACROSS REBOOTS — record the cleanup commands below
#
# UNDO (run from analyst session after incident):
#   Remove-NetFirewallRule -DisplayName "Analyst Allow*"
#   Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Allow -DefaultOutboundAction Allow

$ErrorActionPreference = 'Stop'

function Sec($n) { Write-Output "`n=== $n ===" }

if (-not $AnalystIp) {
  Write-Error "Set `$AnalystIp = '<your-ip>' before running"
  exit 1
}
if ($AnalystIp -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
  Write-Error "AnalystIp '$AnalystIp' does not look like a valid IPv4 address"
  exit 1
}
if (-not $KeepPort) { $KeepPort = 5985 }  # WinRM default; set 22 for SSH

Sec 'PRE-ISOLATION EVIDENCE'
Write-Output "Timestamp:   $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
Write-Output "Analyst IP:  $AnalystIp"
Write-Output "Keep port:   $KeepPort"
Write-Output "Host:        $env:COMPUTERNAME"

Write-Output "`n--- All current established connections (will be severed) ---"
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
  Format-Table -AutoSize

Write-Output "`n--- Current Windows Firewall profile state ---"
Get-NetFirewallProfile -ErrorAction SilentlyContinue |
  Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
  Format-Table -AutoSize

Write-Output "`n--- Existing firewall rules count ---"
$existing = Get-NetFirewallRule -ErrorAction SilentlyContinue | Measure-Object
Write-Output "Existing rules: $($existing.Count)"

Write-Output "`n[CONFIRM] Analyst IP $AnalystIp will keep access on port $KeepPort"
Write-Output "[CONFIRM] ALL OTHER inbound and outbound traffic will be blocked by default"
Write-Output "[CONFIRM] Running on: $env:COMPUTERNAME"

Sec 'LOCK IN ANALYST ACCESS'
# Create allow rules FIRST — before setting default-block (critical ordering)

# Inbound: allow analyst IP on the keep port
$inRule = New-NetFirewallRule `
  -DisplayName "Analyst Allow Inbound - $AnalystIp port $KeepPort" `
  -Direction Inbound `
  -Action Allow `
  -RemoteAddress $AnalystIp `
  -Protocol TCP `
  -LocalPort $KeepPort `
  -Profile Any `
  -Enabled True
Write-Output "[OK] Inbound allow: $AnalystIp → port $KeepPort ($($inRule.Name))"

# Outbound: allow responses to analyst IP
$outRule = New-NetFirewallRule `
  -DisplayName "Analyst Allow Outbound - $AnalystIp port $KeepPort" `
  -Direction Outbound `
  -Action Allow `
  -RemoteAddress $AnalystIp `
  -Protocol TCP `
  -RemotePort $KeepPort `
  -Profile Any `
  -Enabled True
Write-Output "[OK] Outbound allow: → $AnalystIp port $KeepPort ($($outRule.Name))"

# Allow established/related outbound so existing analyst session stays alive
$estRule = New-NetFirewallRule `
  -DisplayName "Analyst Allow Established Outbound" `
  -Direction Outbound `
  -Action Allow `
  -RemoteAddress $AnalystIp `
  -Protocol TCP `
  -Profile Any `
  -Enabled True
Write-Output "[OK] Outbound established allow added"

Sec 'BLOCK ALL OTHER TRAFFIC'
Set-NetFirewallProfile -Profile Domain,Public,Private `
  -DefaultInboundAction Block `
  -DefaultOutboundAction Block
Write-Output "[OK] Default firewall policy set: Block inbound + Block outbound (all profiles)"
Write-Output "[!]  Analyst connection kept via explicit allow rules above"

Sec 'VERIFY — ISOLATION IN PLACE'
Write-Output "`n--- Firewall profiles after isolation ---"
Get-NetFirewallProfile |
  Select-Object Name, DefaultInboundAction, DefaultOutboundAction |
  Format-Table -AutoSize

Write-Output "`n--- Analyst allow rules confirmed ---"
Get-NetFirewallRule -DisplayName "Analyst Allow*" -ErrorAction SilentlyContinue |
  Select-Object DisplayName, Direction, Action, Enabled |
  Format-Table -AutoSize

Write-Output "`n--- Remaining established connections ---"
$remaining = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
  Where-Object { $_.RemoteAddress -ne $AnalystIp }
if ($remaining) {
  Write-Output "[!] Non-analyst established connections remain — may drop shortly:"
  $remaining | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort | Format-Table -AutoSize
} else {
  Write-Output "[OK] No non-analyst established connections"
}

Write-Output "`n--- Analyst connection status ---"
$analystConn = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
  Where-Object { $_.RemoteAddress -eq $AnalystIp }
if ($analystConn) {
  Write-Output "[OK] Analyst connection active: $($analystConn | Select-Object -First 1 -ExpandProperty RemoteAddress):$($analystConn | Select-Object -First 1 -ExpandProperty RemotePort)"
} else {
  Write-Output "(no current established connection from analyst — WinRM session still active via rule)"
}

Sec 'CLEANUP REMINDER'
Write-Output "To RESTORE network access (run from analyst session after incident):"
Write-Output "  Remove-NetFirewallRule -DisplayName 'Analyst Allow*'"
Write-Output "  Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Allow -DefaultOutboundAction Allow"

Sec 'INTEL UPDATE SNIPPET'
$ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
Write-Output @"

intel_update(category="host", id="<HOST_ID>",
  fields="status: contained`nnotes: Host network-isolated at $ts. Analyst $AnalystIp keeps port $KeepPort only. Windows Firewall default-block set.",
  summary="<HOST_ID>: network isolated")

intel_timeline(action="add", entry_type="containment", entry_action="contained",
  target="<HOST_ID>", summary="<HOST_ID> network-isolated — analyst-only Windows Firewall rules")
"@

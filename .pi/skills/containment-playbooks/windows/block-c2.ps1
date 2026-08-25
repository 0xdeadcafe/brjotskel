# containment/windows/block-c2.ps1 — Block attacker C2 IP with Windows Firewall
# Requires: Admin
# State-changing: YES — adds Windows Firewall rules
# Pattern: RECORD → ACT → VERIFY
#
# Parameters:
#   $C2Ip    — attacker C2 IP to block (required)
#   $C2Note  — short label for the rule (optional, default "IR-Block-C2")
#
# Usage:
#   $C2Ip = "185.220.101.45"; <paste>
#
# ⚠️  Record the C2 IP in intel store BEFORE blocking
# ⚠️  Run collect-evidence.ps1 FIRST to capture live connection details

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }

if (-not $C2Ip) {
  Write-Error "Set `$C2Ip = '<ip>' before running"
  exit 1
}
$C2Note = if ($C2Note) { $C2Note } else { "IR-Block-C2" }
$RuleName = "$C2Note-$C2Ip"

Sec 'PRE-BLOCK EVIDENCE'
Write-Output "Timestamp: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
Write-Output "C2 IP:  $C2Ip"
Write-Output "Label:  $RuleName"

Write-Output "`n--- Active connections TO/FROM C2 (snapshot before block) ---"
Get-NetTCPConnection -State Established, TimeWait 2>$null |
  Where-Object { $_.RemoteAddress -eq $C2Ip -or $_.LocalAddress -eq $C2Ip } |
  ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    Write-Output "  $($_.LocalAddress):$($_.LocalPort) → $($_.RemoteAddress):$($_.RemotePort)  PID=$($_.OwningProcess) ($($proc.Name))"
  }

Write-Output "`n--- Current firewall profile state ---"
Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction -AutoSize

Sec 'BLOCK'
# Block outbound to C2
New-NetFirewallRule -DisplayName "$RuleName-Out" `
  -Direction Outbound -RemoteAddress $C2Ip -Action Block -Protocol Any `
  -Description "IR containment: block outbound to attacker C2 $C2Ip" -ErrorAction Stop
Write-Output "[OK] Outbound block rule added: $RuleName-Out"

# Block inbound from C2
New-NetFirewallRule -DisplayName "$RuleName-In" `
  -Direction Inbound -RemoteAddress $C2Ip -Action Block -Protocol Any `
  -Description "IR containment: block inbound from attacker C2 $C2Ip" -ErrorAction Stop
Write-Output "[OK] Inbound block rule added: $RuleName-In"

Sec 'VERIFY — C2 BLOCKED'
Write-Output "--- Firewall rules in place ---"
Get-NetFirewallRule -DisplayName "$RuleName*" 2>$null |
  Get-NetFirewallAddressFilter |
  Select-Object RemoteAddress | Format-Table -AutoSize

$outRule = Get-NetFirewallRule -DisplayName "$RuleName-Out" -ErrorAction SilentlyContinue
$inRule  = Get-NetFirewallRule -DisplayName "$RuleName-In"  -ErrorAction SilentlyContinue

if ($outRule -and $outRule.Enabled) { Write-Output "[OK] Outbound block rule is enabled" }
else { Write-Output "[FAIL] Outbound block rule missing or disabled" }

if ($inRule -and $inRule.Enabled) { Write-Output "[OK] Inbound block rule is enabled" }
else { Write-Output "[FAIL] Inbound block rule missing or disabled" }

Write-Output "`n--- Remaining connections to C2 ---"
$remaining = Get-NetTCPConnection -State Established 2>$null |
  Where-Object { $_.RemoteAddress -eq $C2Ip }
if ($remaining) {
  Write-Output "[!] Connections still established — process may need killing:"
  $remaining | Format-Table LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess -AutoSize
} else {
  Write-Output "[OK] No active connections to $C2Ip"
}

Sec 'INTEL UPDATE SNIPPET'
Write-Output @"

intel_timeline(action="add", entry_type="containment", entry_action="contained",
  target="<HOST_ID>", summary="C2 $C2Ip blocked on <HOST_ID> via Windows Firewall")

intel_update(category="host", id="<HOST_ID>",
  fields="status: contained\nnotes: C2 $C2Ip blocked via New-NetFirewallRule at $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))",
  summary="<HOST_ID>: C2 $C2Ip blocked")
"@

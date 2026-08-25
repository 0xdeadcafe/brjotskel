# gather/windows/enum-reachability.ps1 — Map what this host can reach
# Requires: Any user
# Read-only: YES — probe-only, no writes
# Purpose: Pivot planning — discover live services reachable FROM this host
#          that the harness cannot see directly.
#
# Run inline: remote_exec(session="host01", command="<paste>")

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }

$probePorts = @(22, 80, 135, 139, 443, 445, 1433, 3389, 5985, 5986, 8080, 8443)
$timeoutMs  = 800

function Test-Port($ip, $port) {
  try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $ar  = $tcp.BeginConnect($ip, $port, $null, $null)
    $ok  = $ar.AsyncWaitHandle.WaitOne($timeoutMs, $false)
    $tcp.Close()
    if ($ok) { return $true }
  } catch {}
  return $false
}

Sec 'REACHABILITY HEADER'
Write-Output "Host:      $env:COMPUTERNAME"
Write-Output "Timestamp: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
Write-Output "Probing:   $($probePorts -join ', ')"

Sec 'CANDIDATE TARGETS'

# ARP cache
Write-Output "`n--- ARP cache ---"
$arpIPs = @()
Get-NetNeighbor 2>$null | Where-Object { $_.State -notin @('Unreachable','Incomplete') -and $_.IPAddress -notmatch '^(169\.254|fe80)' } |
  ForEach-Object {
    Write-Output "  $($_.IPAddress)  [$($_.LinkLayerAddress)]  $($_.InterfaceAlias)"
    $arpIPs += $_.IPAddress
  }

# hosts file
Write-Output "`n--- hosts file (non-loopback) ---"
$hostsIPs = @()
Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" 2>$null |
  Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' -and $_ -notmatch '127\.|::1' } |
  ForEach-Object {
    $parts = $_ -split '\s+'
    if ($parts[0] -match '^\d') {
      Write-Output "  $($parts[0])  $($parts[1..($parts.Count-1)] -join ' ')"
      $hostsIPs += $parts[0]
    }
  }

# DNS cache — recent resolutions may hint at internal hosts
Write-Output "`n--- DNS cache (recent A records, first 30) ---"
$dnsIPs = @()
Get-DnsClientCache 2>$null | Where-Object { $_.RecordType -eq 'A' -and $_.Data -notmatch '^(127\.|169\.254)' } |
  Select-Object -First 30 |
  ForEach-Object {
    Write-Output "  $($_.Data)  ($($_.Entry))"
    $dnsIPs += $_.Data
  }

# Routes — look for non-default gateways that suggest internal segments
Write-Output "`n--- Non-default routes ---"
Get-NetRoute 2>$null | Where-Object { $_.DestinationPrefix -ne '0.0.0.0/0' -and $_.DestinationPrefix -ne '::/0' -and $_.NextHop -ne '0.0.0.0' } |
  Format-Table DestinationPrefix, NextHop, InterfaceAlias, RouteMetric -AutoSize

# Combine and deduplicate
$allCandidates = ($arpIPs + $hostsIPs + $dnsIPs) | Sort-Object -Unique |
  Where-Object { $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' }

Sec 'TCP REACHABILITY PROBE'
Write-Output "Probing $($allCandidates.Count) candidate IPs on ports: $($probePorts -join ',')"
Write-Output "Format: OPEN  <host>  <port>`n"

$results = @()
foreach ($ip in $allCandidates) {
  foreach ($port in $probePorts) {
    if (Test-Port $ip $port) {
      Write-Output "OPEN  $ip  $port"
      $results += [PSCustomObject]@{ IP = $ip; Port = $port }
    }
  }
}

if ($results.Count -eq 0) { Write-Output "(no open ports found on candidate IPs)" }

Sec 'NETWORK INTERFACES (PIVOT CONTEXT)'
Get-NetIPAddress 2>$null | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.IPAddress -notmatch '^127\.' } |
  Format-Table IPAddress, PrefixLength, InterfaceAlias -AutoSize

Sec 'REACHABILITY COMPLETE'
Write-Output "Record newly reachable hosts with:"
Write-Output '  intel_add(category="host", id="<id>", data="ip: <ip>\nstatus: suspected\nsource:\n  host: <this-host>\n  method: reachability probe", summary="...")'

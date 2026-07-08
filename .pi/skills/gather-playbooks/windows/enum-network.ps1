# gather/windows/enum-network.ps1 — Network configuration and connections
# Requires: Standard user
# Read-only: YES
# MITRE ATT&CK: T1016 — System Network Configuration Discovery

Write-Output "=== INTERFACES ==="
Get-NetIPAddress -ErrorAction SilentlyContinue | Where-Object { $_.AddressFamily -eq "IPv4" } | Format-Table InterfaceAlias, IPAddress, PrefixLength

Write-Output ""
Write-Output "=== ROUTES ==="
Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -ne "ff00::/8" } | Format-Table DestinationPrefix, NextHop, InterfaceAlias -AutoSize

Write-Output ""
Write-Output "=== DNS SERVERS ==="
Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses } | Format-Table InterfaceAlias, ServerAddresses

Write-Output ""
Write-Output "=== ARP TABLE ==="
Get-NetNeighbor -ErrorAction SilentlyContinue | Where-Object { $_.State -ne "Unreachable" } | Format-Table IPAddress, LinkLayerAddress, State

Write-Output ""
Write-Output "=== LISTENING PORTS ==="
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort | Format-Table LocalAddress, LocalPort, OwningProcess

Write-Output ""
Write-Output "=== ESTABLISHED CONNECTIONS ==="
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Format-Table LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess

Write-Output ""
Write-Output "=== DNS CACHE ==="
Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -First 30 | Format-Table Entry, Data

Write-Output ""
Write-Output "=== NETWORK SHARES ==="
net share 2>$null
Write-Output "--- mapped drives ---"
net use 2>$null

Write-Output ""
Write-Output "=== SMB SESSIONS ==="
Get-SmbSession -ErrorAction SilentlyContinue | Format-Table ClientComputerName, ClientUserName, NumOpens

Write-Output ""
Write-Output "=== FIREWALL PROFILES ==="
Get-NetFirewallProfile -ErrorAction SilentlyContinue | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction

Write-Output ""
Write-Output "=== HOSTS FILE ==="
Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" 2>$null | Where-Object { $_ -notmatch "^#" -and $_ -ne "" }

Write-Output ""
Write-Output "=== WIFI NETWORKS ==="
netsh wlan show networks mode=bssid 2>$null | Select-Object -First 30

# gather/windows/enum-network.ps1 — Network configuration and connections
# Requires: Standard user
# Read-only: YES
# MITRE ATT&CK: T1016 — System Network Configuration Discovery

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }
function Run($c) { Write-Output "PS> $c"; Invoke-Expression $c }

Sec 'INTERFACES'
Run 'Get-NetIPAddress | Where-Object { $_.AddressFamily -eq "IPv4" } | Format-Table InterfaceAlias, IPAddress, PrefixLength'

Sec 'ROUTES'
Run 'Get-NetRoute | Where-Object { $_.DestinationPrefix -ne "ff00::/8" } | Format-Table DestinationPrefix, NextHop, InterfaceAlias -AutoSize'

Sec 'DNS_SERVERS'
Run 'Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses } | Format-Table InterfaceAlias, ServerAddresses'

Sec 'ARP_TABLE'
Run 'Get-NetNeighbor | Where-Object { $_.State -ne "Unreachable" } | Format-Table IPAddress, LinkLayerAddress, State'

Sec 'LISTENING_PORTS'
Run 'Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Format-Table LocalAddress, LocalPort, OwningProcess'

Sec 'ESTABLISHED_CONNECTIONS'
Run 'Get-NetTCPConnection -State Established | Format-Table LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess'

Sec 'DNS_CACHE'
Run 'Get-DnsClientCache | Select-Object -First 30 | Format-Table Entry, Data'

Sec 'NETWORK_SHARES'
Run 'net share'
Write-Output "--- mapped drives ---"
Run 'net use'

Sec 'SMB_SESSIONS'
Run 'Get-SmbSession | Format-Table ClientComputerName, ClientUserName, NumOpens'

Sec 'FIREWALL_PROFILES'
Run 'Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction'

Sec 'HOSTS_FILE'
Run 'Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_ -notmatch "^#" -and $_ -ne "" }'

Sec 'WIFI_NETWORKS'
Run 'netsh wlan show networks mode=bssid | Select-Object -First 30'

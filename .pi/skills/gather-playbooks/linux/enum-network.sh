#!/bin/sh
# gather/linux/enum-network.sh — Network configuration and connections
# Requires: standard user (some commands benefit from root)
# Read-only: YES
# MITRE ATT&CK: T1016 — System Network Configuration Discovery

echo "=== INTERFACES ==="
ip addr 2>/dev/null || ifconfig -a 2>/dev/null

echo ""
echo "=== ROUTES ==="
ip route 2>/dev/null || route -n 2>/dev/null

echo ""
echo "=== ARP TABLE ==="
ip neigh 2>/dev/null || arp -an 2>/dev/null

echo ""
echo "=== LISTENING PORTS ==="
ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null

echo ""
echo "=== ESTABLISHED CONNECTIONS ==="
ss -tnp 2>/dev/null || netstat -tnp 2>/dev/null

echo ""
echo "=== DNS CONFIGURATION ==="
cat /etc/resolv.conf 2>/dev/null
echo "--- nsswitch ---"
grep hosts /etc/nsswitch.conf 2>/dev/null

echo ""
echo "=== HOSTS FILE ==="
cat /etc/hosts 2>/dev/null

echo ""
echo "=== FIREWALL RULES ==="
iptables -L -n -v 2>/dev/null || echo "[*] Cannot read iptables (need root)"
echo "--- nftables ---"
nft list ruleset 2>/dev/null || true

echo ""
echo "=== NETWORK NAMESPACES ==="
ip netns list 2>/dev/null

echo ""
echo "=== WIRELESS ==="
iwconfig 2>/dev/null || true

echo ""
echo "=== VPN / TUNNEL INTERFACES ==="
ip link show type tun 2>/dev/null
ip link show type tap 2>/dev/null
ip link show type wireguard 2>/dev/null
ls /etc/openvpn/*.conf 2>/dev/null && echo "--- OpenVPN configs ---" && grep -l "remote" /etc/openvpn/*.conf 2>/dev/null
ls /etc/wireguard/*.conf 2>/dev/null && echo "--- WireGuard configs ---"

echo ""
echo "=== PROXY SETTINGS ==="
env 2>/dev/null | grep -iE "proxy|socks" || true
cat /etc/proxychains*.conf 2>/dev/null | grep -v "^#" | grep -v "^$" || true

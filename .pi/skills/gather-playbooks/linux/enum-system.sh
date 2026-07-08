#!/bin/sh
# gather/linux/enum-system.sh — System and user enumeration
# Requires: standard user (root for full enumeration)
# Read-only: YES
# MITRE ATT&CK: T1082 — System Information Discovery

echo "=== SYSTEM INFO ==="
hostname 2>/dev/null
uname -a 2>/dev/null
cat /etc/os-release 2>/dev/null || cat /etc/*-release 2>/dev/null | head -10

echo ""
echo "=== CURRENT USER ==="
id 2>/dev/null
whoami 2>/dev/null

echo ""
echo "=== LOGGED IN USERS ==="
w 2>/dev/null
echo "--- last logins ---"
last -20 2>/dev/null

echo ""
echo "=== USER ACCOUNTS ==="
cat /etc/passwd 2>/dev/null
echo "--- users with shells ---"
grep -v "nologin\|/false\|/sync" /etc/passwd 2>/dev/null

echo ""
echo "=== GROUPS ==="
cat /etc/group 2>/dev/null

echo ""
echo "=== SUDOERS ==="
cat /etc/sudoers 2>/dev/null
ls /etc/sudoers.d/ 2>/dev/null && cat /etc/sudoers.d/* 2>/dev/null

echo ""
echo "=== PACKAGES (count) ==="
if command -v dpkg >/dev/null 2>&1; then
  echo "dpkg packages: $(dpkg -l 2>/dev/null | wc -l)"
  dpkg -l 2>/dev/null | tail -30
elif command -v rpm >/dev/null 2>&1; then
  echo "rpm packages: $(rpm -qa 2>/dev/null | wc -l)"
  rpm -qa 2>/dev/null | sort | tail -30
elif command -v apk >/dev/null 2>&1; then
  apk list --installed 2>/dev/null | wc -l
fi

echo ""
echo "=== SERVICES ==="
systemctl list-units --type=service --state=running 2>/dev/null || service --status-all 2>/dev/null || ls /etc/init.d/ 2>/dev/null

echo ""
echo "=== CRON JOBS ==="
echo "--- system crons ---"
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.d/ 2>/dev/null && cat /etc/cron.d/* 2>/dev/null
echo "--- user crons ---"
cut -d: -f1 /etc/passwd 2>/dev/null | while IFS= read -r u; do
  crontab -l -u "$u" 2>/dev/null | grep -v "^#" | grep -v "^$" && echo "  ^ cron for $u"
done

echo ""
echo "=== SUID / SGID FILES ==="
find / -perm -4000 -type f 2>/dev/null | head -30
find / -perm -2000 -type f 2>/dev/null | head -20

echo ""
echo "=== CAPABILITIES ==="
getcap -r / 2>/dev/null | head -20

echo ""
echo "=== KERNEL MODULES ==="
lsmod 2>/dev/null | head -20

echo ""
echo "=== DISK / MOUNTS ==="
df -h 2>/dev/null
echo "--- mounts ---"
mount 2>/dev/null | grep -v "^proc\|^sys\|^cgroup\|^devpts"

echo ""
echo "=== RECENT FILE MODIFICATIONS (last 24h in key dirs) ==="
find /etc /opt /usr/local -mtime -1 -type f 2>/dev/null | head -20

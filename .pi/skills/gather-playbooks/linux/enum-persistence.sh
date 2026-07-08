#!/bin/sh
# gather/linux/enum-persistence.sh — Detect persistence mechanisms
# Requires: root for full coverage, standard user for partial
# Read-only: YES
# MITRE ATT&CK: T1053 (Scheduled Task), T1543 (Systemd Service), T1546 (Event Triggered)

echo "=== CRON — SYSTEM ==="
cat /etc/crontab 2>/dev/null
echo "--- /etc/cron.d/ ---"
ls -la /etc/cron.d/ 2>/dev/null
cat /etc/cron.d/* 2>/dev/null
echo "--- cron.daily/weekly/monthly ---"
ls /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/ /etc/cron.hourly/ 2>/dev/null

echo ""
echo "=== CRON — USER ==="
cut -d: -f1 /etc/passwd 2>/dev/null | while IFS= read -r u; do
  out=$(crontab -l -u "$u" 2>/dev/null | grep -v "^#" | grep -v "^$")
  [ -n "$out" ] && echo "--- $u ---" && echo "$out"
done

echo ""
echo "=== SYSTEMD TIMERS ==="
systemctl list-timers --all --no-pager 2>/dev/null

echo ""
echo "=== SYSTEMD — NON-VENDOR SERVICES ==="
find /etc/systemd/system -name "*.service" -type f 2>/dev/null | while IFS= read -r f; do
  echo "--- $f ---"
  cat "$f" 2>/dev/null
done
find /usr/local/lib/systemd/system -name "*.service" -type f 2>/dev/null | while IFS= read -r f; do
  echo "--- $f ---"
  cat "$f" 2>/dev/null
done
# User services
find /home -path "*/.config/systemd/user/*.service" -type f 2>/dev/null | while IFS= read -r f; do
  echo "--- $f ---"
  cat "$f" 2>/dev/null
done

echo ""
echo "=== RC.LOCAL / INIT ==="
cat /etc/rc.local 2>/dev/null
cat /etc/rc.d/rc.local 2>/dev/null
ls /etc/init.d/ 2>/dev/null | while IFS= read -r svc; do
  # Flag non-package init scripts (no dpkg/rpm ownership)
  dpkg -S "/etc/init.d/$svc" >/dev/null 2>&1 || rpm -qf "/etc/init.d/$svc" >/dev/null 2>&1 || echo "UNPACKAGED: /etc/init.d/$svc"
done

echo ""
echo "=== SHELL PROFILES ==="
for f in /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc; do
  [ -f "$f" ] || continue
  mod=$(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f" 2>/dev/null)
  echo "--- $f (mtime: $mod) ---"
done
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  for f in .bashrc .bash_profile .profile .zshrc .zprofile; do
    [ -f "$d/$f" ] || continue
    # Only flag if modified recently (7 days)
    find "$d/$f" -mtime -7 2>/dev/null | grep -q . && echo "RECENT: $d/$f (modified in last 7 days)"
  done
done

echo ""
echo "=== AUTHORIZED KEYS (persistence via SSH) ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  [ -f "$d/.ssh/authorized_keys" ] || continue
  echo "--- $d/.ssh/authorized_keys ---"
  cat "$d/.ssh/authorized_keys" 2>/dev/null
done

echo ""
echo "=== LD_PRELOAD / LIBRARY HIJACK ==="
cat /etc/ld.so.preload 2>/dev/null && echo "^^^ /etc/ld.so.preload EXISTS"
echo "--- LD_PRELOAD in env ---"
grep -r "LD_PRELOAD" /etc/environment /etc/profile.d/ 2>/dev/null
find /proc/*/environ -readable 2>/dev/null -exec grep -l "LD_PRELOAD" {} \;

echo ""
echo "=== KERNEL MODULES (persistence) ==="
echo "--- modules-load.d ---"
ls /etc/modules-load.d/ 2>/dev/null && cat /etc/modules-load.d/* 2>/dev/null
echo "--- /etc/modules ---"
cat /etc/modules 2>/dev/null | grep -v "^#"

echo ""
echo "=== UDEV RULES ==="
find /etc/udev/rules.d -type f 2>/dev/null | while IFS= read -r f; do
  grep -l "RUN" "$f" 2>/dev/null && echo "  ^ $f contains RUN directive"
done

echo ""
echo "=== AT JOBS ==="
ls /var/spool/cron/atjobs/ 2>/dev/null
atq 2>/dev/null

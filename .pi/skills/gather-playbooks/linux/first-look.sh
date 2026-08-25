#!/bin/sh
# gather/linux/first-look.sh — 30-second situational awareness
# Requires: Any user (root gets more detail)
# Read-only: YES
# Footprint: Zero (no temp files, no disk writes)
# Purpose: Immediate "am I alone? what's happening right now?" before full triage
#
# Run inline: remote_exec(command="<paste>")
# Or pipe:   sh -c "$(cat first-look.sh)"
#
# ⚠️ SUSPICIOUS indicators are noted inline with [!]

set -u

sec(){ printf '\n=== %s ===\n' "$1"; }

sec 'IDENTITY & HOST'
printf 'Host: %s | User: %s | Date: %s\n' \
  "$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null)" \
  "$(id)" \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
uname -r

sec 'WHO IS ON RIGHT NOW'
# [!] Unknown users, multiple root sessions, sessions from unexpected IPs
w 2>/dev/null || who 2>/dev/null

sec 'LAST 10 LOGINS'
# [!] Logins from unexpected IPs, at odd hours, or as service accounts
last -10 2>/dev/null || lastlog 2>/dev/null | head -15

sec 'TOP PROCESSES BY CPU'
# [!] Crypto miners (high CPU), unknown binaries, processes in /tmp /dev/shm
ps auxf --sort=-%cpu 2>/dev/null | head -25 || ps aux | sort -nrk 3 | head -25

sec 'ACTIVE NETWORK CONNECTIONS'
# [!] Outbound to unusual ports (4444, 8080 non-web, IRC 6667, DNS to non-resolver)
# [!] Connections to external IPs from internal-only hosts
# [!] LISTEN on unexpected ports
ss -tunap 2>/dev/null | grep -v "^$" || netstat -tunap 2>/dev/null | grep -v "^$"

sec 'LISTENING SERVICES'
# [!] Unexpected listeners: high ports, 0.0.0.0 binds, processes in /tmp
ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null

sec 'ATTACKER STAGING AREAS'
# [!] Any files here that aren't expected system temp: scripts, binaries, encoded blobs
echo "--- /tmp ---"
ls -la /tmp/ 2>/dev/null | grep -v "^total"
echo "--- /dev/shm ---"
ls -la /dev/shm/ 2>/dev/null | grep -v "^total"
echo "--- /var/tmp ---"
ls -la /var/tmp/ 2>/dev/null | grep -v "^total"
echo "--- /run/user ---"
ls -la /run/user/ 2>/dev/null

sec 'FILES MODIFIED IN LAST HOUR'
# [!] Modified binaries, new scripts, changed configs, new authorized_keys
find / -mmin -60 -type f \
  -not -path '/proc/*' -not -path '/sys/*' -not -path '/run/*' \
  -not -path '/var/log/*' -not -path '/var/cache/*' \
  2>/dev/null | head -30

sec 'SCHEDULED EXECUTION (IMMEDIATE THREATS)'
# [!] Cron entries with curl/wget, base64, /tmp paths, reverse shells
echo "--- user crontab ---"
crontab -l 2>/dev/null || echo "(none or not permitted)"
echo "--- /etc/cron.d ---"
ls -la /etc/cron.d/ 2>/dev/null
echo "--- recent systemd timers ---"
systemctl list-timers --no-pager 2>/dev/null | head -10

sec 'FIREWALL STATE'
# [!] Empty ruleset on a production host, recently flushed rules
iptables -L -n --line-numbers 2>/dev/null | head -25 || \
  nft list ruleset 2>/dev/null | head -25 || \
  echo "(cannot read firewall — not root or no iptables/nft)"

sec 'QUICK PERSISTENCE HINTS'
# [!] Unusual entries in rc.local, ld.so.preload, or shell profiles
cat /etc/rc.local 2>/dev/null | grep -v "^#" | grep -v "^$" | head -5
cat /etc/ld.so.preload 2>/dev/null
grep -r "bash\|sh\|python\|curl\|wget\|nc" /etc/profile.d/ 2>/dev/null | grep -v "^#" | head -5

sec 'ENVIRONMENT SUMMARY'
printf 'CPUs: %s | RAM: %s | Disk: %s\n' \
  "$(nproc 2>/dev/null || echo '?')" \
  "$(free -h 2>/dev/null | awk '/^Mem:/{print $2}' || echo '?')" \
  "$(df -h / 2>/dev/null | awk 'NR==2{print $2 " (" $5 " used)"}' || echo '?')"
echo ""
echo "[first-look complete — run full triage for deeper analysis]"

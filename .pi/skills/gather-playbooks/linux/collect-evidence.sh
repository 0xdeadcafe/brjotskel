#!/bin/sh
# gather/linux/collect-evidence.sh — Pre-containment volatile evidence collection
# Requires: root (recommended; non-root gets partial coverage)
# Read-only: YES — captures state only, no modifications
# Footprint: stdout only — no files written on target
# Purpose: Bag volatile evidence BEFORE any containment action changes it
#
# ⚠️  RUN THIS BEFORE kill-process, block-c2, disable-account, or isolate-host
#     Volatile state (connections, process env, open handles) dies when you act.
#
# Usage:
#   remote_exec(session="host01", command="<paste>") — capture output to harness
#   Pull result to: workspace/evidence/<host>/volatile-<timestamp>.txt
#
# What this captures:
#   - Full process tree with args (dies when process is killed)
#   - Suspicious process environment variables (C2 URLs, tokens)
#   - Live network connections with PIDs (dies at isolation)
#   - Open file handles including deleted-but-open binaries
#   - Loaded kernel modules (rootkit check baseline)
#   - Auth log tail (last 200 lines before isolation cuts access)
#   - Staging area file hashes (binary hashes before deletion)
#   - Recently modified files in sensitive paths
#   - Shell history across all users
#   - ARP and routing table (network topology before isolation)
#   - Firewall state snapshot

set -u

sec(){ printf '\n=== %s [%s] ===\n' "$1" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"; }
hsh(){ sha256sum "$1" 2>/dev/null || md5sum "$1" 2>/dev/null || printf '(no hash util) %s\n' "$1"; }

sec 'EVIDENCE HEADER'
printf 'Host:      %s\n' "$(hostname 2>/dev/null || uname -n)"
printf 'Collected: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'Collector: %s\n' "$(id)"
printf 'Kernel:    %s\n' "$(uname -r)"
printf 'Uptime:    %s\n' "$(uptime 2>/dev/null || cat /proc/uptime 2>/dev/null)"

sec 'PROCESS TREE — FULL COMMAND LINES'
# ⚠️  Volatile: process may rename itself, path may be unlinked after kill
ps auxfww 2>/dev/null || ps auxww 2>/dev/null

sec 'PROCESS DETAILS — BINARY PATH AND HASH'
# Hash every running process binary that is not a standard system path
# Do this BEFORE killing — the file may be deleted on exit
ps auxww 2>/dev/null | awk 'NR>1 && $11!="" {print $11}' | sort -u | while IFS= read -r bin; do
  case "$bin" in /usr/*|/bin/*|/sbin/*|/lib/*|/lib64/*) continue ;; esac
  [ -f "$bin" ] || continue
  printf 'BINARY: %s  ' "$bin"
  hsh "$bin"
done

sec 'PROCESS ENVIRONMENT — SUSPICIOUS PIDS'
# Look for C2 addresses, tokens, encoded payloads in process env
# Only processes outside standard OS paths
ls /proc 2>/dev/null | grep -E '^[0-9]+$' | while IFS= read -r pid; do
  exe=$(readlink /proc/"$pid"/exe 2>/dev/null) || continue
  case "$exe" in /usr/*|/bin/*|/sbin/*|/lib/*|/lib64/*|/opt/*) continue ;; esac
  env_out=$(tr '\0' '\n' < /proc/"$pid"/environ 2>/dev/null | grep -v '^$' || true)
  [ -n "$env_out" ] && printf '\n--- PID %s (%s) ---\n%s\n' "$pid" "$exe" "$env_out"
done

sec 'DELETED-BUT-OPEN FILE HANDLES'
# Attacker technique: unlink binary from disk, keep running; hash disappears from fs
ls /proc 2>/dev/null | grep -E '^[0-9]+$' | while IFS= read -r pid; do
  ls -la /proc/"$pid"/fd 2>/dev/null | grep '(deleted)' | while IFS= read -r line; do
    printf 'PID %s: %s\n' "$pid" "$line"
  done
done

sec 'ACTIVE NETWORK CONNECTIONS — WITH PIDS'
# ⚠️  Volatile: lost at process kill or isolation
ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null

sec 'ESTABLISHED CONNECTIONS — REMOTE ENDPOINTS (C2 CANDIDATES)'
printf 'RemoteIP:Port  PID/Process\n'
ss -tunap 2>/dev/null | awk '/ESTAB/{print $5, $6}' | sort -u || \
  netstat -tunap 2>/dev/null | awk '/ESTABLISHED/{print $5, $7}' | sort -u

sec 'LISTENING SERVICES — SNAPSHOT'
ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null

sec 'OPEN FILE HANDLES — NETWORK AND SUSPICIOUS'
lsof -nP 2>/dev/null | grep -E 'deleted|LISTEN|ESTABLISHED|UDP|IPv4|IPv6|REG.*DEL' | head -150 || \
  echo "(lsof not available — check /proc/<pid>/fd manually)"

sec 'LOADED KERNEL MODULES'
# Baseline before rootkit module removal; some rootkits hide from lsmod
lsmod 2>/dev/null
printf '\nModule count: %s\n' "$(lsmod 2>/dev/null | wc -l)"

sec 'ATTACKER STAGING AREAS — FILE LISTING AND HASHES'
for d in /tmp /dev/shm /var/tmp /run/shm; do
  [ -d "$d" ] || continue
  echo "--- $d ---"
  ls -laR "$d" 2>/dev/null | head -50
  find "$d" -maxdepth 3 -type f 2>/dev/null | while IFS= read -r f; do
    hsh "$f"
  done
done

sec 'RECENTLY MODIFIED FILES (LAST 24H) — SENSITIVE PATHS'
find /tmp /var/tmp /dev/shm /root /etc /usr/local/bin /usr/local/sbin \
  -mmin -1440 -type f 2>/dev/null | head -80

sec 'RECENTLY MODIFIED — SYSTEM BINARIES'
find /bin /sbin /usr/bin /usr/sbin -mmin -10080 -type f 2>/dev/null | head -40

sec 'AUTH LOG — LAST 200 LINES'
# ⚠️  Volatile access: isolation may cut log access
tail -200 /var/log/auth.log 2>/dev/null || \
  tail -200 /var/log/secure 2>/dev/null || \
  journalctl -n 200 -u ssh -u sshd --no-pager 2>/dev/null || \
  echo "(auth log not accessible)"

sec 'SYSLOG/JOURNAL — LAST 200 LINES'
tail -200 /var/log/syslog 2>/dev/null || \
  tail -200 /var/log/messages 2>/dev/null || \
  journalctl -n 200 --no-pager 2>/dev/null || \
  echo "(syslog not accessible)"

sec 'SCHEDULED JOBS SNAPSHOT'
# Capture current cron state before eradication
echo "--- /etc/crontab ---"
cat /etc/crontab 2>/dev/null
echo "--- /etc/cron.d/ ---"
ls -la /etc/cron.d/ 2>/dev/null
cat /etc/cron.d/* 2>/dev/null
echo "--- user crontabs ---"
cut -d: -f1 /etc/passwd 2>/dev/null | while IFS= read -r u; do
  out=$(crontab -l -u "$u" 2>/dev/null | grep -v '^#' | grep -v '^$') || continue
  [ -n "$out" ] && printf '  %s: %s\n' "$u" "$out"
done

sec 'SHELL HISTORY — ALL USERS (LAST 50 LINES EACH)'
for home in /root /home/*; do
  [ -d "$home" ] || continue
  for hf in .bash_history .zsh_history .sh_history .history; do
    [ -f "$home/$hf" ] || continue
    printf '\n--- %s/%s ---\n' "$home" "$hf"
    tail -50 "$home/$hf" 2>/dev/null
  done
done

sec 'SSH AUTHORIZED KEYS — ALL USERS'
for home in /root /home/*; do
  [ -f "$home/.ssh/authorized_keys" ] || continue
  printf '--- %s/.ssh/authorized_keys ---\n' "$home"
  cat "$home/.ssh/authorized_keys" 2>/dev/null
done

sec 'ARP TABLE'
arp -n 2>/dev/null || ip neigh show 2>/dev/null

sec 'ROUTING TABLE'
ip route show 2>/dev/null || netstat -rn 2>/dev/null

sec 'DNS CONFIG'
cat /etc/resolv.conf 2>/dev/null
cat /etc/hosts | grep -v '^#' | grep -v '^$' | head -20

sec 'FIREWALL STATE SNAPSHOT'
# Capture before isolation flushes/replaces rules
iptables -L -n -v --line-numbers 2>/dev/null || \
  nft list ruleset 2>/dev/null || \
  echo "(no iptables/nft access)"

sec 'SYSTEMD SERVICES — ACTIVE NON-VENDOR'
systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -40

sec 'EVIDENCE COLLECTION COMPLETE'
printf '\nTimestamp: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Next steps:"
echo "  1. Save this output: workspace/evidence/<host>/volatile-<timestamp>.txt"
echo "  2. Record C2 IPs from ESTABLISHED CONNECTIONS above"
echo "  3. Record attacker binary hashes from BINARY HASH section"
echo "  4. Then proceed with containment"

#!/bin/sh
# gather/macos/collect-evidence.sh — Pre-containment volatile evidence collection
# Requires: root/admin for full coverage
# Read-only: YES — captures state only, no modifications
# Sensitive-output: YES — may print credential material or credential-bearing artifacts
# Footprint: stdout only — no files written on target
# Purpose: Bag volatile evidence BEFORE any containment action changes it
#
# ⚠️  RUN THIS BEFORE kill-process, block-c2, or any isolation action
#     Live connections, process env, and launchd state die when you act.
#
# Usage:
#   remote_exec(session="mac01", command="<paste>") — capture output to harness
#   Pull result to: workspace/evidence/<host>/volatile-<timestamp>.txt

set -u

sec(){ printf '\n=== %s [%s] ===\n' "$1" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"; }
hsh(){ shasum -a 256 "$1" 2>/dev/null || md5 "$1" 2>/dev/null || printf '(no hash) %s\n' "$1"; }

sec 'EVIDENCE HEADER'
printf 'Host:      %s\n' "$(hostname)"
printf 'Collected: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'Collector: %s\n' "$(id)"
sw_vers 2>/dev/null
printf 'Uptime:    %s\n' "$(uptime)"

sec 'PROCESS TREE — FULL COMMAND LINES'
# ⚠️  Volatile: dies when process is killed
ps auxww 2>/dev/null

sec 'PROCESS BINARY HASHES — NON-STANDARD PATHS'
# Hash attacker binaries before killing
ps auxww 2>/dev/null | awk 'NR>1 && $11!="" {print $11}' | sort -u | while IFS= read -r bin; do
  case "$bin" in /usr/*|/bin/*|/sbin/*|/Applications/*|/System/*) continue ;; esac
  [ -f "$bin" ] || continue
  printf 'BINARY: %s  ' "$bin"
  hsh "$bin"
done

sec 'ACTIVE NETWORK CONNECTIONS — WITH PIDS'
# ⚠️  Volatile: lost when process dies or host is isolated
lsof -i -nP 2>/dev/null | grep -E 'ESTABLISHED|LISTEN' | head -100 || \
  netstat -an 2>/dev/null | grep -E 'ESTABLISHED|LISTEN' | head -100

sec 'ESTABLISHED CONNECTIONS — REMOTE ENDPOINTS (C2 CANDIDATES)'
lsof -i -nP 2>/dev/null | awk '/ESTABLISHED/{print $9, $1, $2}' | sort -u || \
  netstat -an 2>/dev/null | awk '/ESTABLISHED/{print $5}' | sort -u

sec 'OPEN FILE HANDLES — NETWORK AND DELETED FILES'
lsof -nP 2>/dev/null | grep -E 'deleted|LISTEN|ESTABLISHED|IPv4|IPv6' | head -100

sec 'LOADED KERNEL EXTENSIONS'
# Baseline before rootkit kext removal
kextstat 2>/dev/null | grep -v 'com.apple' | head -40

sec 'ATTACKER STAGING AREAS — FILE LISTING AND HASHES'
for d in /tmp /private/tmp /var/tmp /Users/Shared; do
  [ -d "$d" ] || continue
  echo "--- $d ---"
  ls -laR "$d" 2>/dev/null | grep -v 'com.apple' | head -40
  find "$d" -maxdepth 3 -type f 2>/dev/null | while IFS= read -r f; do
    hsh "$f"
  done
done

sec 'RECENTLY MODIFIED FILES (LAST 24H) — SENSITIVE PATHS'
find /tmp /var/tmp /private/tmp /Users/Shared /usr/local/bin /usr/local/sbin \
  -mmin -1440 -type f 2>/dev/null | head -60

sec 'RECENTLY MODIFIED — LAUNCH ITEMS'
find /Library/LaunchDaemons /Library/LaunchAgents \
  "$HOME/Library/LaunchAgents" \
  -mmin -10080 -type f 2>/dev/null | while IFS= read -r f; do
  printf 'MODIFIED: %s\n' "$f"
  hsh "$f"
done

sec 'LAUNCHD STATE — ALL LOADED JOBS'
launchctl list 2>/dev/null | head -100

sec 'LAUNCHD — NON-APPLE DAEMONS AND AGENTS'
launchctl list 2>/dev/null | grep -v 'com.apple\|PID\|-' | head -40
echo "--- /Library/LaunchDaemons (non-apple) ---"
ls /Library/LaunchDaemons/ 2>/dev/null | grep -v 'com.apple'
echo "--- /Library/LaunchAgents (non-apple) ---"
ls /Library/LaunchAgents/ 2>/dev/null | grep -v 'com.apple'
echo "--- ~/Library/LaunchAgents ---"
ls "$HOME/Library/LaunchAgents/" 2>/dev/null | grep -v 'com.apple'

sec 'AUTH LOG — LAST 200 LINES'
# ⚠️  Log access lost after isolation
tail -200 /var/log/auth.log 2>/dev/null || \
  log show --last 2h --predicate 'subsystem == "com.apple.authd"' --no-pager 2>/dev/null | tail -100 || \
  echo "(auth log not accessible)"

sec 'UNIFIED LOG — RECENT EXEC AND NETWORK'
log show --last 1h --predicate 'eventMessage contains "spawn" OR eventMessage contains "exec" OR category == "network"' \
  --info --no-pager 2>/dev/null | tail -100 || echo "(log show not available)"

sec 'SCHEDULED JOBS SNAPSHOT'
echo "--- crontab ---"
crontab -l 2>/dev/null || echo "(none)"
echo "--- /etc/cron.d ---"
ls -la /etc/cron.d/ 2>/dev/null
echo "--- at queue ---"
atq 2>/dev/null

sec 'SHELL HISTORY — ALL USERS (LAST 50 LINES EACH)'
for home in /root /Users/*; do
  [ -d "$home" ] || continue
  for hf in .bash_history .zsh_history .sh_history; do
    [ -f "$home/$hf" ] || continue
    printf '\n--- %s/%s ---\n' "$home" "$hf"
    tail -50 "$home/$hf" 2>/dev/null
  done
done

sec 'SSH AUTHORIZED KEYS — ALL USERS'
for home in /root /Users/*; do
  [ -f "$home/.ssh/authorized_keys" ] || continue
  printf '--- %s/.ssh/authorized_keys ---\n' "$home"
  cat "$home/.ssh/authorized_keys" 2>/dev/null
done

sec 'ARP TABLE'
arp -an 2>/dev/null || arp -n 2>/dev/null

sec 'ROUTING TABLE'
netstat -rn 2>/dev/null

sec 'DNS CONFIG'
cat /etc/resolv.conf 2>/dev/null
cat /etc/hosts | grep -v '^#' | grep -v '^$' | head -20
scutil --dns 2>/dev/null | head -20

sec 'FIREWALL STATE SNAPSHOT'
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null
/usr/libexec/ApplicationFirewall/socketfilterfw --listapps 2>/dev/null | head -20
pfctl -sr 2>/dev/null || echo "(pf not enabled or no access)"

sec 'SECURITY STATE'
echo "SIP:       $(csrutil status 2>/dev/null)"
echo "FileVault: $(fdesetup status 2>/dev/null)"
echo "Gatekeeper:$(spctl --status 2>/dev/null)"

sec 'EVIDENCE COLLECTION COMPLETE'
printf '\nTimestamp: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Next steps:"
echo "  1. Save this output: workspace/evidence/<host>/volatile-<timestamp>.txt"
echo "  2. Record C2 IPs from ESTABLISHED CONNECTIONS above"
echo "  3. Record attacker binary hashes from BINARY HASH section"
echo "  4. Then proceed with containment"

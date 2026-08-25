#!/bin/sh
# gather/macos/first-look.sh — 30-second situational awareness
# Requires: Any user (root/admin gets more detail)
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
  "$(hostname)" \
  "$(id)" \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sw_vers 2>/dev/null
uname -r

sec 'WHO IS ON RIGHT NOW'
# [!] Unknown users, multiple sessions, screen sharing active
w 2>/dev/null || who 2>/dev/null
# Check for screen sharing / VNC
launchctl list 2>/dev/null | grep -i "screensharing\|vnc\|ARDAgent" && echo "[!] Remote desktop/screen sharing active"

sec 'LAST 10 LOGINS'
# [!] Logins from unexpected sources, at odd hours
last -10 2>/dev/null

sec 'TOP PROCESSES BY CPU'
# [!] Unknown binaries, processes in /tmp, crypto miners, reverse shells
ps aux | sort -nrk 3 | head -25

sec 'ACTIVE NETWORK CONNECTIONS'
# [!] Outbound to unusual ports, connections to external IPs from internal host
# [!] Processes connecting out: look for python, perl, bash, nc, ncat, curl with persistent connections
lsof -i -nP 2>/dev/null | grep -E 'ESTABLISHED|LISTEN' | head -30 || \
  netstat -an 2>/dev/null | grep -E 'ESTABLISHED|LISTEN' | head -30

sec 'LISTENING SERVICES'
# [!] Unexpected listeners on high ports
lsof -i -nP 2>/dev/null | grep LISTEN || \
  netstat -an 2>/dev/null | grep LISTEN

sec 'ATTACKER STAGING AREAS'
# [!] Executables, scripts, hidden files in temp/shared locations
echo "--- /tmp ---"
ls -la /tmp/ 2>/dev/null | grep -v "^total" | grep -v "com.apple"
echo "--- /private/tmp ---"
ls -la /private/tmp/ 2>/dev/null | grep -v "^total" | grep -v "com.apple"
echo "--- /Users/Shared ---"
ls -la /Users/Shared/ 2>/dev/null | grep -v "^total"
echo "--- user Downloads (recent) ---"
find ~/Downloads -mmin -60 -type f 2>/dev/null | head -10

sec 'FILES MODIFIED IN LAST HOUR'
# [!] Modified system binaries, new launch agents/daemons, changed shell profiles
find / -mmin -60 -type f \
  -not -path '/System/Volumes/*' \
  -not -path '/private/var/folders/*' \
  -not -path '/private/var/log/*' \
  -not -path '/Library/Caches/*' \
  -not -path '*/com.apple.*' \
  2>/dev/null | head -30

sec 'LAUNCHD PERSISTENCE (QUICK CHECK)'
# [!] Non-Apple launch agents/daemons, recently modified plists
echo "--- User LaunchAgents ---"
ls -la ~/Library/LaunchAgents/ 2>/dev/null | grep -v "com.apple"
echo "--- System LaunchDaemons (non-Apple) ---"
ls -la /Library/LaunchDaemons/ 2>/dev/null | grep -v "com.apple"
echo "--- System LaunchAgents (non-Apple) ---"
ls -la /Library/LaunchAgents/ 2>/dev/null | grep -v "com.apple"
# Recently modified
echo "--- Modified in last hour ---"
find /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents \
  -mmin -60 -type f 2>/dev/null

sec 'CRON & AT'
# [!] Any cron entries for current user, unusual scheduled jobs
crontab -l 2>/dev/null || echo "(no crontab)"
atq 2>/dev/null | head -5

sec 'SECURITY STATE'
# [!] SIP disabled, FileVault off on a laptop, firewall disabled
echo "--- SIP ---"
csrutil status 2>/dev/null || echo "(cannot check SIP)"
echo "--- Firewall ---"
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || \
  defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null
echo "--- FileVault ---"
fdesetup status 2>/dev/null || echo "(cannot check FileVault)"
echo "--- Gatekeeper ---"
spctl --status 2>/dev/null || echo "(cannot check Gatekeeper)"

sec 'SSH STATE'
# [!] Unexpected authorized_keys entries, SSH agent with loaded keys
echo "--- authorized_keys ---"
cat ~/.ssh/authorized_keys 2>/dev/null | wc -l | xargs printf '%s entries\n'
echo "--- SSH agent ---"
ssh-add -l 2>/dev/null || echo "(no agent)"
echo "--- sshd running? ---"
launchctl list 2>/dev/null | grep ssh && echo "[!] sshd is active"

sec 'ENVIRONMENT SUMMARY'
printf 'CPUs: %s | RAM: %s | Disk: %s\n' \
  "$(sysctl -n hw.ncpu 2>/dev/null || echo '?')" \
  "$(sysctl -n hw.memsize 2>/dev/null | awk '{printf "%.0fGB", $1/1073741824}' || echo '?')" \
  "$(df -h / 2>/dev/null | awk 'NR==2{print $2 " (" $5 " used)"}' || echo '?')"
echo ""
echo "[first-look complete — run full triage for deeper analysis]"

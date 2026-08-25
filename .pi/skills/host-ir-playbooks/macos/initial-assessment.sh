#!/bin/sh
# host-ir-playbooks/macos/initial-assessment.sh — Attacker-perspective compromise investigation
# Requires: root (some sections degrade gracefully without it)
# State-changing: NO — read-only investigation
#
# Purpose: Determine whether this macOS host is compromised. Focused on high-signal
# attacker artifacts — not broad evidence collection. Use macos/live-response.sh
# (gather-playbooks) for full volatile capture before containment.
#
# Covers: host role, live attacker activity, non-Apple persistence, automation/pivot
# artifacts, recent suspicious execution, credential exposure clues, security state.
#
# Usage: remote_exec(session="mac01", command="<paste>")

set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
run(){ printf '$ %s\n' "$*"; sh -c "$*" 2>/dev/null || true; }

sec OBJECTIVE
printf '%s\n' 'macOS initial compromise assessment: host role, live attacker activity, non-Apple persistence, automation/pivot artifacts, recent suspicious execution, credential exposure, and security state.'

sec HOST_ROLE
run 'hostname'
run 'id'
run 'sw_vers'
run 'uname -a'
run 'uptime'
run 'system_profiler SPHardwareDataType SPSoftwareDataType 2>/dev/null | grep -E "Model|OS X|macOS|Version|Processor|Memory|Serial"'

sec LIVE_ATTACKER_ACTIVITY
echo "--- Active sessions ---"
run 'who'
run 'w'

echo "--- Outbound and listening connections ---"
run 'lsof -i -n -P 2>/dev/null | grep -E "ESTABLISHED|LISTEN"'
run 'netstat -anv 2>/dev/null | grep -E "ESTABLISHED|LISTEN"'

echo "--- Suspicious processes (non-Apple paths) ---"
# Highlight processes not in standard Apple paths
run 'ps aux 2>/dev/null | awk '\''NR==1 || ($11 !~ /^\/System\// && $11 !~ /^\/usr\// && $11 !~ /^\/sbin\// && $11 !~ /^\/bin\// && $11 !~ /^\[/ && $11 != "") {print}'\'' | head -60'

echo "--- Staging areas ---"
run 'find /tmp /private/tmp /var/tmp -maxdepth 2 -type f -mtime -3 2>/dev/null | sort | head -50'

sec PERSISTENCE_TARGETED
echo "--- Non-Apple LaunchDaemons ---"
# Flag plists not under /System/Library and not from Apple-signed sources
run 'find /Library/LaunchDaemons -maxdepth 1 -name "*.plist" 2>/dev/null | sort | while read p; do
  label=$(defaults read "$p" Label 2>/dev/null)
  program=$(defaults read "$p" Program 2>/dev/null || defaults read "$p" ProgramArguments 2>/dev/null | head -1)
  printf "[%s] label=%s program=%s\n" "$(basename $p)" "$label" "$program"
done'

echo "--- Per-user LaunchAgents (all users) ---"
run 'for home in /Users/*; do
  [ -d "$home" ] || continue
  [ -d "$home/Library/LaunchAgents" ] || continue
  u=$(basename "$home")
  find "$home/Library/LaunchAgents" -maxdepth 1 -name "*.plist" 2>/dev/null | while read p; do
    label=$(defaults read "$p" Label 2>/dev/null)
    program=$(defaults read "$p" ProgramArguments 2>/dev/null | head -1)
    printf "user=%s [%s] label=%s program=%s\n" "$u" "$(basename $p)" "$label" "$program"
  done
done'

echo "--- Global LaunchAgents ---"
run 'find /Library/LaunchAgents -maxdepth 1 -name "*.plist" 2>/dev/null | sort | while read p; do
  label=$(defaults read "$p" Label 2>/dev/null)
  program=$(defaults read "$p" Program 2>/dev/null || defaults read "$p" ProgramArguments 2>/dev/null | head -1)
  printf "[%s] label=%s program=%s\n" "$(basename $p)" "$label" "$program"
done'

echo "--- Login items (macOS 13+ Background Task Manager) ---"
run 'sfltool dumpbtm 2>/dev/null | grep -E "url|name|developer" | head -60'

echo "--- Shell and profile hooks ---"
run 'for home in /Users/*; do
  [ -d "$home" ] || continue
  u=$(basename "$home")
  for f in "$home/.zshrc" "$home/.zprofile" "$home/.zlogin" "$home/.bashrc" "$home/.bash_profile" "$home/.profile"; do
    [ -f "$f" ] || continue
    printf "# %s (%s)\n" "$f" "$u"
    cat "$f" 2>/dev/null | grep -vE "^#|^$" | head -20
  done
done'

echo "--- Cron (rarely used on macOS but check anyway) ---"
run 'crontab -l 2>/dev/null || echo "(no root crontab)"'
run 'for home in /Users/*; do
  u=$(basename "$home")
  crontab -l -u "$u" 2>/dev/null | grep -v "^#\|^$" | while read l; do printf "user=%s: %s\n" "$u" "$l"; done
done'

sec AUTOMATION_AND_PIVOT_ARTIFACTS
echo "--- SSH config and known hosts ---"
run 'for home in /Users/* /root; do
  [ -d "$home" ] || continue
  u=$(basename "$home")
  [ -f "$home/.ssh/config" ] && { printf "\n# %s/.ssh/config\n" "$u"; cat "$home/.ssh/config" 2>/dev/null; }
  [ -f "$home/.ssh/known_hosts" ] && printf "# %s known_hosts: %d entries\n" "$u" "$(wc -l < $home/.ssh/known_hosts 2>/dev/null)"
done'

echo "--- VPN / network profiles (mobileconfig and ovpn) ---"
run 'find /Library /private/var/preferences -maxdepth 5 \( -name "*.mobileconfig" -o -name "*.ovpn" -o -name "*.conf" \) 2>/dev/null | grep -Ei "vpn|network|profile" | head -30'

echo "--- Ansible / automation artifacts ---"
run 'find /Users /etc /opt -maxdepth 4 \( -name "ansible.cfg" -o -name "inventory" -o -name "hosts" \) 2>/dev/null | grep -Ei "ansible" | head -20'

echo "--- AWS/GCP/Azure credential files ---"
run 'find /Users -maxdepth 4 \( -name "credentials" -o -name "*.json" -o -name "*.env" \) 2>/dev/null | grep -Ei "aws|gcp|azure|\.env" | head -20'

sec RECENT_SUSPICIOUS_EXECUTION
echo "--- Unified log: spawn/exec events (last 24h) ---"
run 'log show --last 24h --style compact \
  --predicate "process == \"launchd\" OR eventMessage CONTAINS[c] \"execve\" OR eventMessage CONTAINS[c] \"spawn\"" \
  2>/dev/null | tail -200'

echo "--- Unified log: auth and sudo events (last 24h) ---"
run 'log show --last 24h --style compact \
  --predicate "subsystem == \"com.apple.pam\" OR process CONTAINS[c] \"sudo\" OR process == \"sshd\" OR process == \"SecurityAgent\"" \
  2>/dev/null | tail -100'

echo "--- Shell history: suspicious command hits ---"
run 'for home in /Users/*; do
  [ -d "$home" ] || continue
  u=$(basename "$home")
  for hist in "$home/.zsh_history" "$home/.bash_history"; do
    [ -f "$hist" ] || continue
    printf "\n# %s (%s)\n" "$hist" "$u"
    grep -nE "curl|wget|python|ruby|osascript|xterm|bash -[ic]|sh -[ic]|exec|nc |ncat|socat|scp|rsync|base64|openssl|brew install.*[nN]cat|brew install.*socat" "$hist" 2>/dev/null | head -50
  done
done'

echo "--- Recently modified executables and scripts ---"
run 'find /Users /tmp /private/tmp /opt -maxdepth 5 \( -name "*.sh" -o -name "*.py" -o -name "*.rb" -o -perm -u+x \) \
  -newer /etc/passwd -mtime -7 -type f 2>/dev/null | grep -v ".Trash\|.cache\|Library/Caches" | head -40'

sec CREDENTIAL_EXPOSURE
echo "--- Keychain query (metadata only — no secrets) ---"
run 'security find-generic-password -a "" 2>/dev/null | grep -E "svce|acct|labl" | head -40'
run 'security find-internet-password -a "" 2>/dev/null | grep -E "srvr|acct|labl|ptcl" | head -40'

echo "--- SSH private key material ---"
run 'find /Users -maxdepth 4 \( -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" -o -name "*.pem" -o -name "*.key" \) \
  -type f 2>/dev/null | head -20'

echo "--- Browser credential hints ---"
run 'find /Users -maxdepth 6 \( -name "Login Data" -o -name "Cookies" \) 2>/dev/null | grep -Ei "safari|chrome|firefox" | head -20'

echo "--- Environment and config credential leaks ---"
run 'for home in /Users/*; do
  [ -d "$home" ] || continue
  find "$home" -maxdepth 3 -name ".env" -o -name ".env.*" 2>/dev/null | while read f; do
    printf "# %s\n" "$f"
    grep -iE "secret|password|token|key|aws|gcp|azure" "$f" 2>/dev/null | head -5
  done
done'

sec SECURITY_STATE
run 'fdesetup status 2>/dev/null'
run 'csrutil status 2>/dev/null'
run 'spctl --status 2>/dev/null'
run 'softwareupdate --list 2>/dev/null | grep -i "critical\|security" | head -10'
run 'systemsetup -getremotelogin 2>/dev/null'
run 'systemsetup -getremoteappleevents 2>/dev/null'
run 'defaults read /Library/Preferences/com.apple.screensharing 2>/dev/null | grep -i "enabled\|state" | head -5'

sec SUSPICIOUS_SIGNS
printf '%s\n' '[!] Flag for investigation:'
printf '%s\n' '  - Non-Apple LaunchDaemons or LaunchAgents (especially with RunAtLoad=true or KeepAlive=true)'
printf '%s\n' '  - sfltool dumpbtm entries not from known software vendors'
printf '%s\n' '  - Processes running from /tmp, /Users/*/Downloads, /var/tmp, or unusual paths'
printf '%s\n' '  - Remote Login enabled and Active Directory or unknown SSH keys present'
printf '%s\n' '  - Shell history: download+execute patterns (curl|sh, wget|bash, python -c)'
printf '%s\n' '  - Unified log: rapid execve chains, unexpected sudo activity, sshd logins outside business hours'
printf '%s\n' '  - AWS/cloud credential files present on developer machines (blast radius = cloud environment)'
printf '%s\n' '  - Keychain entries for unexpected services or VPN profiles'

sec NEXT_ACTIONS
printf '%s\n' '[*] If suspicious artifacts confirmed, record findings with intel_add:'
printf '%s\n' '  - compromised user account → intel_add(category="account", ...)'
printf '%s\n' '  - C2 IP or domain observed → intel_add(category="host", ...) + note in host record'
printf '%s\n' '  - SSH keys or cloud tokens → intel_add(category="credential", ...)'
printf '%s\n' '[*] Follow with:'
printf '%s\n' '  - macos/enum-credentials.sh — deep keychain and SSH material sweep'
printf '%s\n' '  - macos/enum-remote-access-artifacts.sh — pivot potential (VNC, SSH, Wi-Fi)'
printf '%s\n' '  - macos/enum-launchd.sh — full loaded job inventory'
printf '%s\n' '  - macos/enum-unified-logs.sh — extended log window if needed'
printf '%s\n' '  - macos/collect-evidence.sh (gather-playbooks) — full volatile capture before containment'

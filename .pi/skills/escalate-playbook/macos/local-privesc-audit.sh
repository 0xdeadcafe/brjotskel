#!/bin/sh
set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
run(){ printf '$ %s\n' "$*"; sh -c "$*" 2>/dev/null || true; }

sec OBJECTIVE
printf '%s\n' 'Assess macOS privilege-escalation paths using native commands: sudo, setuid binaries, writable privileged paths, launchd helpers, and GTFOBins-style candidates.'

sec CURRENT_CONTEXT
run 'id'
run 'whoami'
run 'groups'
run 'sudo -n -l'

sec SUDO_AND_GTFObins
run 'sudo -l'
run 'sudo -l 2>/dev/null | grep -iE "vim|vi|find|bash|sh|env|python|python3|perl|ruby|awk|less|more|tar|cp|mv|tee|rsync|osascript"'

sec SETUID_AND_HELPERS
run 'find / -perm -4000 -type f 2>/dev/null | sort | head -250'
run 'find / -perm -4000 -type f 2>/dev/null | grep -E "/(bash|sh|find|vim|python|python3|perl|ruby|awk|env|cp|rsync|osascript)$"'
run 'ls -l /Library/PrivilegedHelperTools 2>/dev/null'

sec WRITABLE_PRIVILEGED_PATHS
run 'for d in /usr/local/bin /usr/local/sbin /Library/Scripts /Library/LaunchAgents /Library/LaunchDaemons /Applications; do [ -e "$d" ] && ls -ldO "$d"; done'
run 'find /Library /usr/local -maxdepth 3 -type d -writable 2>/dev/null | head -200'
run 'find /Library /usr/local -maxdepth 3 -type f -writable 2>/dev/null | head -200'

sec LAUNCHD_AND_AUTOMATION
run 'find /Library/LaunchAgents /Library/LaunchDaemons ~/Library/LaunchAgents -maxdepth 2 -type f 2>/dev/null | sort | head -250'
run 'grep -RniE "Program|ProgramArguments|RunAtLoad|KeepAlive|WatchPaths" /Library/LaunchAgents /Library/LaunchDaemons ~/Library/LaunchAgents 2>/dev/null | head -250'
run 'crontab -l'

sec AUTH_AND_POLICY_HINTS
run 'dseditgroup -o checkmember -m "$(whoami)" admin'
run 'defaults read /Library/Preferences/com.apple.loginwindow 2>/dev/null'
run 'security authorizationdb read system.install.software 2>/dev/null | head -80'
run 'sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "select service,client,auth_value from access;" 2>/dev/null | head -80'

sec SYSTEM_VERSION
run 'sw_vers'
run 'uname -a'

sec SUSPICIOUS_MISCONFIGS
printf '%s\n' '[!] High-signal findings: passwordless sudo for interpreter/editor tools, unusual third-party setuid binaries, writable launchd plists or helper scripts, writable privileged helper tools, and admin-group access combined with weak policy prompts.'

sec EVIDENCE_TO_PRESERVE
printf '%s\n' '[*] Preserve exact sudoers lines, helper-tool paths, launchd plist contents, permissions, ownership, and referenced scripts before any change.'

sec NEXT_ACTIONS
printf '%s\n' '[*] If exploitation guidance is requested, map validated sudo or setuid binaries to GTFOBins-like semantics and keep state-changing steps clearly separated.'

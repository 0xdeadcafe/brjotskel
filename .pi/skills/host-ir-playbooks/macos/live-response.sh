#!/bin/sh
set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
run(){ printf '$ %s\n' "$*"; sh -c "$*" 2>/dev/null || true; }

sec OBJECTIVE
printf '%s\n' 'macOS live-response triage: host role, live sessions, launchd persistence, recent execution clues, and security state.'

sec HOST_CONTEXT
run 'hostname'
run 'id'
run 'sw_vers'
run 'uname -a'
run 'uptime'
run 'system_profiler SPSoftwareDataType 2>/dev/null'

sec LIVE_ACTIVITY
run 'who'
run 'w'
run 'ps aux'
run 'netstat -anv'
run 'lsof -i -n -P 2>/dev/null'
run 'launchctl list'
run '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I 2>/dev/null'
run 'systemsetup -getremotelogin 2>/dev/null'
run 'systemsetup -getremoteappleevents 2>/dev/null'

sec PERSISTENCE_CLUES
run 'find /Library/LaunchDaemons /Library/LaunchAgents -maxdepth 1 \( -type f -o -type l \) 2>/dev/null | sort'
run 'grep -R -nE "Program|ProgramArguments|RunAtLoad|KeepAlive|WatchPaths" /Library/LaunchDaemons /Library/LaunchAgents 2>/dev/null'
run 'defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null'
for home in /Users/*; do
  [ -d "$home" ] || continue
  printf '## %s\n' "$home"
  find "$home"/Library/LaunchAgents -maxdepth 1 \( -type f -o -type l \) 2>/dev/null | sort
  ls -la "$home"/.zshrc "$home"/.zprofile "$home"/.zlogin "$home"/.bash_profile "$home"/.bashrc "$home"/.profile 2>/dev/null || true
done

sec RECENT_EXECUTION
run 'log show --last 12h --style compact --predicate "process == \"launchd\" OR eventMessage CONTAINS[c] \"exec\" OR eventMessage CONTAINS[c] \"spawn\"" | tail -150'
run 'find /tmp /private/tmp -maxdepth 2 -type f -mtime -3 2>/dev/null | sort | head -100'
run 'find /Users -maxdepth 3 -type f \( -name ".zsh_history" -o -name ".bash_history" \) 2>/dev/null -exec tail -50 {} \;'
run 'for home in /Users/*; do [ -d "$home" ] || continue; printf "## %s\n" "$home"; plutil -p "$home"/Library/Safari/LastSession.plist 2>/dev/null; done'

sec SECURITY_STATE
run 'fdesetup status 2>/dev/null'
run 'csrutil status 2>/dev/null'
run 'spctl --status 2>/dev/null'

sec SUSPICIOUS_SIGNS
printf '%s\n' '[!] Review unexpected LaunchAgents/LaunchDaemons, autologin usage, remote login/screensharing exposure, suspicious airport/Wi-Fi associations, Safari last-session clues to admin portals, suspicious shell history, and unusual files staged in temporary directories.'

sec NEXT_ACTIONS
printf '%s\n' '[*] If suspicious launchd jobs or user artifacts are confirmed, record the host, user, and reachable peers with intel_add, preserve plist paths and recent log excerpts, and follow with macos/enum-remote-access-artifacts.sh plus targeted persistence or credential review.'

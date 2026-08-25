#!/bin/sh
# gather/macos/enum-remote-access-artifacts.sh — Enumerate Wi-Fi, VNC, Safari session, and remote-access user artifacts
# Requires: standard user (some paths may need elevation)
# Read-only: YES
# MITRE ATT&CK: T1021 / evidence collection

set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
run(){ printf '$ %s\n' "$*"; sh -c "$*" 2>/dev/null || true; }

sec OBJECTIVE
printf '%s\n' 'Collect airport/Wi-Fi details, VNC exposure, Safari last-session artifacts, SSH history, and related remote-access traces on macOS.'

sec WIFI_AND_AIRPORT
run '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I'
run '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s | head -40'
run 'defaults read /Library/Preferences/SystemConfiguration/com.apple.airport.preferences'
run 'networksetup -listpreferredwirelessnetworks en0 2>/dev/null'

sec REMOTE_ACCESS_SERVICES
run 'systemsetup -getremotelogin 2>/dev/null'
run 'systemsetup -getremoteappleevents 2>/dev/null'
run 'launchctl print system/com.openssh.sshd 2>/dev/null | head -80'
run 'launchctl print system/com.apple.screensharing 2>/dev/null | head -80'
run 'launchctl print system/com.apple.RemoteDesktop.agent 2>/dev/null | head -80'
run 'defaults read /Library/Preferences/com.apple.RemoteManagement 2>/dev/null'

sec VNC_AND_SCREEN_SHARING_HINTS
run 'defaults read /Library/Preferences/com.apple.VNCSettings 2>/dev/null'
run 'defaults read /var/db/launchd.db/com.apple.launchd/overrides.plist 2>/dev/null | egrep "screensharing|ARDAgent|ssh"'
run 'find /Library/Preferences /Users -maxdepth 4 \( -name "com.apple.ScreenSharing.plist" -o -name "com.apple.RemoteDesktop.plist" -o -name "com.apple.VNCSettings.txt" \) 2>/dev/null | sort'

sec SAFARI_LAST_SESSION
for home in /Users/*; do
  [ -d "$home" ] || continue
  printf '## %s\n' "$home"
  run "ls -la '$home'/Library/Safari 2>/dev/null"
  run "plutil -p '$home'/Library/Safari/LastSession.plist 2>/dev/null"
  run "find '$home'/Library/Safari -maxdepth 2 -type f 2>/dev/null | sort | head -50"
done

sec SSH_AND_REMOTE_USER_ARTIFACTS
for home in /Users/* /var/root; do
  [ -d "$home" ] || continue
  printf '## %s\n' "$home"
  run "find '$home'/.ssh -maxdepth 2 -type f 2>/dev/null -exec ls -la {} \;"
  run "sed -n '1,120p' '$home'/.ssh/config 2>/dev/null"
  run "sed -n '1,120p' '$home'/.ssh/known_hosts 2>/dev/null"
  run "tail -80 '$home'/.zsh_history 2>/dev/null"
  run "tail -80 '$home'/.bash_history 2>/dev/null"
done

sec BROWSER_AND_URL_SHORTCUT_HINTS
for home in /Users/*; do
  [ -d "$home" ] || continue
  printf '## %s\n' "$home"
  run "find '$home'/Desktop '$home'/Downloads '$home'/Documents -maxdepth 2 \( -name '*.webloc' -o -name '*.inetloc' -o -name '*.rdp' \) 2>/dev/null | sort | head -80"
done

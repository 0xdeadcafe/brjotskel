#!/bin/sh
set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
run(){ printf '$ %s\n' "$*"; sh -c "$*" 2>/dev/null || true; }

sec INTERFACES
run 'ifconfig -a'
run 'networksetup -listallhardwareports 2>/dev/null'

sec ROUTING
run 'netstat -rn'
run 'route -n get default 2>/dev/null'

sec DNS
run 'scutil --dns'
run 'scutil --proxy'

sec WIFI
run '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I 2>/dev/null'
run 'defaults read /Library/Preferences/SystemConfiguration/com.apple.airport.preferences 2>/dev/null'

sec CONNECTIONS
run 'netstat -anv'
run 'lsof -i -n -P 2>/dev/null'

sec NEIGHBORS
run 'arp -an'
run 'netstat -nr -f inet6 2>/dev/null'

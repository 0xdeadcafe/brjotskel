#!/bin/sh
set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
run(){ printf '$ %s\n' "$*"; sh -c "$*" 2>/dev/null || true; }

sec HOST
run 'hostname'
run 'id'
run 'sw_vers'
run 'uname -a'
run 'uptime'

sec HARDWARE
run 'system_profiler SPHardwareDataType SPSoftwareDataType 2>/dev/null'

sec USERS
run 'dscl . list /Users'
run 'dscl . list /Groups'
run 'who'
run 'last | head -50'

sec PROCESSES
run 'ps aux'
run 'launchctl list'

sec SERVICES_AND_JOBS
run 'ls -la /Library/LaunchDaemons /Library/LaunchAgents 2>/dev/null'
run 'find /System/Library/LaunchDaemons /System/Library/LaunchAgents -maxdepth 1 -type f 2>/dev/null | sort'
run 'find /Library/LaunchDaemons /Library/LaunchAgents -maxdepth 1 -type f 2>/dev/null | sort'

sec STORAGE_AND_SECURITY
run 'diskutil apfs list 2>/dev/null'
run 'fdesetup status 2>/dev/null'
run 'csrutil status 2>/dev/null'

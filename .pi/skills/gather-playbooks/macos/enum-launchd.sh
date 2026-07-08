#!/bin/sh
set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
run(){ printf '$ %s\n' "$*"; sh -c "$*" 2>/dev/null || true; }

sec LOADED_JOBS
run 'launchctl list'
run 'launchctl print system 2>/dev/null'
run 'launchctl print gui/$(id -u) 2>/dev/null'

sec SYSTEM_PLISTS
run 'find /System/Library/LaunchDaemons /System/Library/LaunchAgents /Library/LaunchDaemons /Library/LaunchAgents -maxdepth 1 \( -type f -o -type l \) 2>/dev/null | sort'
run 'grep -R -nE "Label|Program|ProgramArguments|RunAtLoad|KeepAlive|WatchPaths|QueueDirectories|StandardOutPath|StandardErrorPath" /System/Library/LaunchDaemons /System/Library/LaunchAgents /Library/LaunchDaemons /Library/LaunchAgents 2>/dev/null'

sec USER_PLISTS
for d in /Users/*/Library/LaunchAgents; do
  [ -d "$d" ] || continue
  printf '## %s\n' "$d"
  find "$d" -maxdepth 1 \( -type f -o -type l \) 2>/dev/null | sort
  grep -R -nE 'Label|Program|ProgramArguments|RunAtLoad|KeepAlive|WatchPaths|QueueDirectories|StandardOutPath|StandardErrorPath' "$d" 2>/dev/null || true
done

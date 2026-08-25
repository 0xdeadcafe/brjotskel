#!/bin/sh
set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
run(){ printf '$ %s\n' "$*"; sh -c "$*" 2>/dev/null || true; }

sec SAFARI
for home in /Users/*; do
  [ -d "$home" ] || continue
  printf '## %s\n' "$home"
  ls -la "$home"/Library/Safari 2>/dev/null || true
  find "$home"/Library/Safari -maxdepth 2 -type f 2>/dev/null | sort | head -100
  plutil -p "$home"/Library/Safari/LastSession.plist 2>/dev/null || true
done

sec CHROME
for home in /Users/*; do
  [ -d "$home" ] || continue
  printf '## %s\n' "$home"
  ls -la "$home"/Library/Application\ Support/Google/Chrome/Default 2>/dev/null || true
  find "$home"/Library/Application\ Support/Google/Chrome -maxdepth 3 -type f 2>/dev/null | egrep 'History|Cookies|Login Data|Bookmarks|Preferences' | head -100 || true
done

sec FIREFOX
for home in /Users/*; do
  [ -d "$home" ] || continue
  printf '## %s\n' "$home"
  ls -la "$home"/Library/Application\ Support/Firefox/Profiles 2>/dev/null || true
  find "$home"/Library/Application\ Support/Firefox/Profiles -maxdepth 2 -type f 2>/dev/null | egrep 'places.sqlite|cookies.sqlite|key4.db|logins.json|prefs.js' | head -100 || true
done

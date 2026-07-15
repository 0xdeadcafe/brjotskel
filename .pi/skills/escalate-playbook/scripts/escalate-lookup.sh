#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
REF_DIR="$ROOT/shell-commands/reference"

usage() {
  cat <<'EOF'
Usage: escalate-lookup.sh [--search TERM] [--topic linux|windows|lotl|lolbas|gtfobins|all]

Examples:
  ./scripts/escalate-lookup.sh --search sudo
  ./scripts/escalate-lookup.sh --search SeImpersonatePrivilege
  ./scripts/escalate-lookup.sh --topic windows
  ./scripts/escalate-lookup.sh --topic gtfobins
EOF
}

search=
topic=all

while [[ $# -gt 0 ]]; do
  case "$1" in
    --search)
      search=${2:-}
      shift 2
      ;;
    --topic)
      topic=${2:-}
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

case "$topic" in
  linux)
    files=("$REF_DIR/privilege-escalation.md" "$REF_DIR/linux-ir.md" "$REF_DIR/gtfobins-full.md")
    ;;
  windows)
    files=("$REF_DIR/privilege-escalation.md" "$REF_DIR/windows-powershell.md" "$REF_DIR/lolbas-full.md")
    ;;
  lotl)
    files=("$REF_DIR/living-off-the-land.md")
    ;;
  lolbas)
    files=("$REF_DIR/lolbas-full.md")
    ;;
  gtfobins)
    files=("$REF_DIR/gtfobins-full.md")
    ;;
  all)
    files=(
      "$REF_DIR/privilege-escalation.md"
      "$REF_DIR/living-off-the-land.md"
      "$REF_DIR/lolbas-full.md"
      "$REF_DIR/gtfobins-full.md"
      "$REF_DIR/windows-powershell.md"
      "$REF_DIR/linux-ir.md"
    )
    ;;
  *)
    echo "Unknown topic: $topic" >&2
    exit 1
    ;;
esac

if [[ -z "$search" ]]; then
  printf '%s\n' "# Reference files"
  printf '%s\n' "${files[@]}"
  exit 0
fi

rg -n -i --context 2 --color never --glob '*.md' "$search" "${files[@]}"

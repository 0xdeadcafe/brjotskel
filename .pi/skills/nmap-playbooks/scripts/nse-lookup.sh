#!/usr/bin/env bash
set -euo pipefail

DB=${NMAP_SCRIPT_DB:-/usr/share/nmap/scripts/script.db}
DIR=${NMAP_SCRIPT_DIR:-/usr/share/nmap/scripts}

usage() {
  cat <<'EOF'
Usage: nse-lookup.sh [--category NAME] [--search TERM] [--file NAME] [--show-path]

Examples:
  ./scripts/nse-lookup.sh --category safe
  ./scripts/nse-lookup.sh --category vuln --search smb
  ./scripts/nse-lookup.sh --search http
  ./scripts/nse-lookup.sh --file smb-enum-shares.nse
EOF
}

category=
search=
file=
show_path=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --category)
      category=${2:-}
      shift 2
      ;;
    --search)
      search=${2:-}
      shift 2
      ;;
    --file)
      file=${2:-}
      shift 2
      ;;
    --show-path)
      show_path=1
      shift
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

if [[ ! -f "$DB" ]]; then
  echo "Missing script db: $DB" >&2
  exit 1
fi

awk -v category="$category" -v search="$search" -v file="$file" -v show_path="$show_path" -v dir="$DIR" '
  {
    line=$0
    name=""
    cats=""
    if (match(line, /filename = "([^"]+)"/, m)) name=m[1]
    if (match(line, /categories = \{([^}]*)\}/, c)) cats=c[1]
    gsub(/"|,/, "", cats)
    gsub(/[[:space:]]+/, " ", cats)
    if (name == "") next
    ok=1
    if (category != "" && index(" " cats " ", " " category " ") == 0) ok=0
    hay=tolower(name " " cats)
    if (search != "" && index(hay, tolower(search)) == 0) ok=0
    if (file != "" && name != file) ok=0
    if (!ok) next
    if (show_path == 1) {
      print dir "/" name "\t[" cats "]"
    } else {
      print name "\t[" cats "]"
    }
  }
' "$DB" | sort

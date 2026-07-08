#!/usr/bin/env bash
# shell-lookup.sh — Search the shell-commands reference corpus
# Usage:
#   ./shell-lookup.sh --platform <powershell|cmd|linux> --category <category>
#   ./shell-lookup.sh --search "<keyword>"
#   ./shell-lookup.sh --list-categories

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REF_DIR="$SCRIPT_DIR/../reference"

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  --platform <powershell|cmd|linux>   Filter by platform
  --category <category>               Filter by category
  --search <keyword>                  Literal search across references
  --list-categories                   Show available categories
  -h, --help                          Show this help

Categories:
  processes, network, persistence, users, files, logs,
  memory, registry, services, lateral-movement, credentials, exfiltration,
  privesc, tunneling, persist-implant, lateral-offense, containment,
  eradication, anti-forensics, browser, evidence, lolbas, gtfobins

Examples:
  $(basename "$0") --platform powershell --category persistence
  $(basename "$0") --search "scheduled task"
  $(basename "$0") --platform linux --search "cron"
EOF
  exit 0
}

list_categories() {
  echo "Available categories:"
  echo ""
  echo "  === Defensive (Blue Team) ==="
  echo "  processes        - Process investigation and analysis"
  echo "  network          - Network connections, DNS, firewall"
  echo "  persistence      - Persistence mechanism detection"
  echo "  users            - User and account investigation"
  echo "  files            - File system investigation"
  echo "  logs             - Event log and syslog analysis"
  echo "  memory           - Memory and runtime analysis"
  echo "  registry         - Windows registry forensics"
  echo "  services         - Service/daemon investigation"
  echo "  lateral-movement - Lateral movement artifact detection"
  echo "  credentials      - Credential and authentication"
  echo "  exfiltration     - Data exfiltration indicators"
  echo ""
  echo "  === Offensive (Red/Purple Team) ==="
  echo "  privesc          - Privilege escalation techniques"
  echo "  tunneling        - Tunneling, relaying, and pivoting"
  echo "  persist-implant  - Persistence implantation methods"
  echo "  lateral-offense  - Lateral movement execution"
  echo "  containment      - Active containment and isolation actions"
  echo "  eradication      - Persistence removal and verification actions"
  echo ""
  echo "  === Detection & Forensics ==="
  echo "  anti-forensics   - Timestomping, log tampering, evidence destruction"
  echo "  browser          - Browser history, extensions, cached credentials"
  echo "  evidence         - Evidence collection safety and hashing"
  echo "  lolbas           - LOLBAS binary abuse detection"
  echo "  gtfobins         - GTFOBins binary abuse detection"
  exit 0
}

# Map platform to reference files
platform_files() {
  local platform="$1"
  case "$platform" in
    powershell|ps|ps1)
      echo "$REF_DIR/windows-powershell.md $REF_DIR/network-forensics.md $REF_DIR/persistence-detection.md $REF_DIR/lateral-movement.md $REF_DIR/lolbas-full.md $REF_DIR/anti-forensics-evidence.md $REF_DIR/privilege-escalation.md $REF_DIR/persistence-implant.md $REF_DIR/lateral-movement-offensive.md $REF_DIR/active-containment.md $REF_DIR/living-off-the-land.md $REF_DIR/tunneling-relaying.md"
      ;;
    cmd|windows-cmd)
      echo "$REF_DIR/windows-cmd.md $REF_DIR/network-forensics.md $REF_DIR/persistence-detection.md $REF_DIR/lateral-movement.md $REF_DIR/lolbas-full.md $REF_DIR/anti-forensics-evidence.md $REF_DIR/active-containment.md $REF_DIR/living-off-the-land.md $REF_DIR/tunneling-relaying.md"
      ;;
    linux|unix|bash)
      echo "$REF_DIR/linux-ir.md $REF_DIR/network-forensics.md $REF_DIR/persistence-detection.md $REF_DIR/lateral-movement.md $REF_DIR/gtfobins-full.md $REF_DIR/anti-forensics-evidence.md $REF_DIR/privilege-escalation.md $REF_DIR/persistence-implant.md $REF_DIR/lateral-movement-offensive.md $REF_DIR/tunneling-relaying.md $REF_DIR/active-containment.md $REF_DIR/living-off-the-land.md"
      ;;
    *)
      echo "$REF_DIR/*.md"
      ;;
  esac
}

# Map category to section headers/keywords to grep for
category_pattern() {
  local category="$1"
  case "$category" in
    processes|process)     echo "Process|process|tasklist|ps aux|Get-Process|Get-CimInstance Win32_Process" ;;
    network|net)          echo "Network|network|netstat|ss -|Get-NetTCP|DNS|dns|firewall|ARP|route" ;;
    persistence|persist)  echo "Persistence|persistence|Scheduled Task|cron|Run Key|Service|startup|autostart|WMI Event" ;;
    users|user|account)   echo "User|user|Account|account|logon|login|whoami|Get-LocalUser" ;;
    files|file|filesystem) echo "File System|prefetch|Alternate Data Streams|ADS|Get-ChildItem|find /|ls -la|dir /|Get-FileHash|sha256sum" ;;
    logs|log|events)      echo "Log|log|Event|event|wevtutil|Get-WinEvent|journalctl|syslog|auth.log" ;;
    memory|mem)           echo "Memory|memory|inject|thread|lsof|proc|volatile" ;;
    registry|reg)         echo "Registry|registry|reg query|HKLM|HKCU|Get-ItemProperty" ;;
    services|service)     echo "Service|service|systemctl|sc query|Get-Service|Win32_Service|daemon|launchctl" ;;
    lateral-movement|lateral) echo "Lateral Movement|RDP|SMB|PsExec|WMI|WinRM|SSH|pivot|admin share|Remote Desktop|Pass-the-Hash|wmiexec|psexec" ;;
    credentials|creds)    echo "Credential|Kerberos|LSASS|SAM|shadow|cmdkey|klist|DPAPI|keychain|ssh key|authorized_keys|secretsdump|vault|autologon" ;;
    exfiltration|exfil)   echo "exfil|staging|large file|compress|archive|upload|download" ;;
    privesc|privilege-escalation) echo "Privilege|privilege|SUID|sudo|UAC|SeImpersonate|Token|Potato|kernel exploit|capability" ;;
    tunneling|tunnel|relay) echo "tunnel|Tunnel|relay|Relay|SSH.*-[LRD]|chisel|ligolo|socat|netsh.*portproxy|SOCKS|proxy|NTLM|iodine|dns2tcp|ptunnel" ;;
    persist-implant|persistence-implant) echo "implant|Create|create|Register-Scheduled|schtasks /create|New-Service|sc create|crontab|authorized_keys|systemd|WMI.*subscription|webshell|BITS" ;;
    lateral-offense|lateral-movement-offensive) echo "psexec|wmiexec|smbexec|crackmapexec|evil-winrm|Invoke-Command|Enter-PSSession|Pass-the-Hash|Pass-the-Ticket|DCSync|secretsdump|Mimikatz|pth" ;;
    containment|active-containment) echo "containment|Containment|kill process|stop-service|disable account|block c2|firewall block|isolate host|quarantine|netsh advfirewall|iptables|ufw|kill -9|taskkill" ;;
    eradication|remove-persistence) echo "eradication|Eradication|remove persistence|delete scheduled task|sc delete|Remove-Item|reg delete|systemctl disable|crontab -r|authorized_keys|verification|verify" ;;
    anti-forensics|antiforensics|timestomp) echo "timestomp|Timestomp|SetCreationTime|SetLastWriteTime|touch.*-t|log.*clear|Clear-EventLog|wevtutil cl|truncate|shred|1102|104" ;;
    browser|browsers)  echo "Chrome|Firefox|Edge|browser|History|places.sqlite|Login Data|extensions|Downloads" ;;
    evidence|collection|chain-of-custody) echo "evidence|hash|SHA256|chain of custody|collect|Export-Csv|sha256sum|mkdir.*evidence" ;;
    lolbas)           echo "certutil|bitsadmin|mshta|rundll32|regsvr32|wmic|forfiles|pcalua|MpCmdRun|esentutl|comsvcs|rdrleakdiag|diskshadow|wbadmin" ;;
    gtfobins)         echo "SUID|sudo|GTFOBins|find.*-exec|vim.*:!|python.*os\.system|perl.*exec|awk.*system|env /bin|reverse shell" ;;
    *)                    echo "$category" ;;
  esac
}

# Parse arguments
PLATFORM=""
CATEGORY=""
SEARCH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform|-p) PLATFORM="$2"; shift 2 ;;
    --category|-c) CATEGORY="$2"; shift 2 ;;
    --search|-s) SEARCH="$2"; shift 2 ;;
    --list-categories) list_categories ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

if [[ -z "$PLATFORM" && -z "$CATEGORY" && -z "$SEARCH" ]]; then
  usage
fi

# Determine files to search
if [[ -n "$PLATFORM" ]]; then
  FILES=$(platform_files "$PLATFORM")
else
  FILES="$REF_DIR/*.md"
fi

# Build search pattern
if [[ -n "$SEARCH" ]]; then
  PATTERN="$SEARCH"
elif [[ -n "$CATEGORY" ]]; then
  PATTERN=$(category_pattern "$CATEGORY")
else
  # Platform only — show available reference files and top-level headings
  for f in $FILES; do
    if [[ -f "$f" ]]; then
      echo "=== $(basename "$f") ==="
      grep -nE '^#|^## ' "$f" | head -20
      echo ""
    fi
  done
  exit 0
fi

# Search and display context
echo "Searching for: $PATTERN"
echo "Platform: ${PLATFORM:-all}"
echo "Category: ${CATEGORY:-any}"
echo "---"

for f in $FILES; do
  if [[ -f "$f" ]]; then
    if [[ -n "$SEARCH" ]]; then
      results=$(grep -inF "$PATTERN" "$f" 2>/dev/null || true)
      if [[ -n "$results" ]]; then
        echo ""
        echo "=== $(basename "$f") ==="
        grep -inF -B 2 -A 5 "$PATTERN" "$f" 2>/dev/null | head -100
      fi
    else
      results=$(grep -inE "$PATTERN" "$f" 2>/dev/null || true)
      if [[ -n "$results" ]]; then
        echo ""
        echo "=== $(basename "$f") ==="
        grep -inE -B 2 -A 5 "$PATTERN" "$f" 2>/dev/null | head -100
      fi
    fi
  fi
done

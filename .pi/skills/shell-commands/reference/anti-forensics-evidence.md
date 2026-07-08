# Anti-Forensics Detection & Evidence Collection Safety

> Sources: BTFM, RTFM v3, MITRE ATT&CK Defense Evasion (TA0005), Indicator Removal (T1070)
> Purpose: Detect attacker anti-forensics + ensure analysts collect evidence safely

---

## Timestomping Detection (T1070.006)

### Windows

```powershell
# Files where creation time > modification time (impossible normally)
Get-ChildItem -Path C:\ -Recurse -Force -EA 0 | Where-Object {
  $_.CreationTime -gt $_.LastWriteTime
} | Select-Object FullName, CreationTime, LastWriteTime | Select-Object -First 30

# Files with timestamps matching known timestomp patterns (exact midnight, year 2000, etc.)
Get-ChildItem -Path C:\Users -Recurse -Force -EA 0 | Where-Object {
  $_.CreationTime.TimeOfDay -eq [timespan]::Zero -or
  $_.CreationTime.Year -lt 2010
} | Select-Object FullName, CreationTime, LastWriteTime

# Compare $MFT timestamps with $STANDARD_INFORMATION timestamps
# (Requires: MFT parsing — native tool: fsutil usn readjournal C:)
fsutil usn readjournal C: csv | findstr /i "filename"

# USN Journal — shows real file operations regardless of timestamp manipulation
fsutil usn readjournal C: | Select-String "Close" | Select-Object -Last 50

# $MFT last modification vs current file system timestamps
# Check NTFS $SI vs $FN timestamps (requires raw NTFS access or MFT export)
```

```cmd
:: Check for timestamp anomalies via forfiles
:: Files "modified" before they were "created" in directory listing
forfiles /P C:\Users /S /D -365 /C "cmd /c if @isdir==FALSE echo @path @fdate @ftime"
```

### Linux

```bash
# Files where mtime < ctime (modified before metadata change — impossible without tampering)
find / -not -path "/proc/*" -not -path "/sys/*" -newer /etc/hostname -printf "%T+ %C+ %p\n" 2>/dev/null |
  awk -F' ' '{if ($1 < $2) print}' | head -30

# Files with suspicious timestamps (year 1970, exact midnight)
find / -not -path "/proc/*" -newermt "1970-01-02" ! -newermt "1970-01-03" 2>/dev/null
find / -not -path "/proc/*" -newermt "2000-01-01" ! -newermt "2000-01-02" 2>/dev/null

# Detect touch command in history/logs
grep -h "touch\s*-t\|touch\s*-d\|touch\s*--date" /root/.bash_history /home/*/.bash_history 2>/dev/null

# Compare stat output — look for Birth (btime) vs Modify/Change inconsistencies
stat /path/to/suspicious/file
# If Modify < Birth → timestomped (on ext4 with birth time support)

# Check auditd for timestamp manipulation
ausearch -sc utimes -sc utimensat -ts recent 2>/dev/null
```

## Log Tampering / Clearing Detection (T1070.001, T1070.002)

### Windows

```powershell
# Event log clearing events (Security log Event ID 1102)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -EA 0 |
  Select-Object TimeCreated, @{N='ClearedBy';E={$_.Properties[1].Value}}, Message

# System log cleared (Event ID 104)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=104} -EA 0 |
  Select-Object TimeCreated, Message

# Check if logs are suspiciously small/empty
Get-WinEvent -ListLog * -EA 0 | Where-Object { $_.RecordCount -eq 0 -and $_.IsEnabled } |
  Select-Object LogName, RecordCount, LastWriteTime

# Check log file sizes (empty = likely cleared)
Get-ChildItem "C:\Windows\System32\winevt\Logs\*.evtx" |
  Where-Object { $_.Length -lt 69632 } |  # Minimum viable evtx is ~68KB
  Select-Object Name, Length, LastWriteTime | Sort-Object Length

# Audit policy gaps (logging intentionally disabled)
auditpol /get /category:*

# Check if PowerShell logging is disabled (attacker may have turned it off)
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -EA 0
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -EA 0

# Sysmon service stopped?
Get-Service Sysmon* -EA 0 | Select-Object Name, Status, StartType

# Windows Defender exclusions (attacker may add paths)
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess
Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension
```

```cmd
:: Quick check for cleared logs
wevtutil qe Security /q:"*[System[(EventID=1102)]]" /f:text /rd:true /c:5
wevtutil qe System /q:"*[System[(EventID=104)]]" /f:text /rd:true /c:5

:: Audit policy status
auditpol /get /category:*
```

### Linux

```bash
# Check if logs were truncated (small or empty)
find /var/log -type f -size 0 -ls 2>/dev/null
find /var/log -type f -size -100c -ls 2>/dev/null

# Check for log gaps (missing time periods in auth.log)
awk '{print $1, $2, $3}' /var/log/auth.log 2>/dev/null | uniq | head -30

# Detect log file deletion/truncation in recent history
grep -hE "truncate|shred|rm.*\/var\/log|>.*\/var\/log|echo.*>.*log" /root/.bash_history /home/*/.bash_history 2>/dev/null

# Check if journald was vacuumed (logs rotated/deleted)
journalctl --disk-usage
journalctl --verify 2>&1 | grep -i "fail\|error\|corrupt"

# Check for auditd tampering
systemctl status auditd 2>/dev/null
cat /etc/audit/auditd.conf 2>/dev/null | grep -i "max_log_file_action\|space_left_action"

# Syslog configuration tampering
cat /etc/rsyslog.conf 2>/dev/null | grep -v "^#\|^$"
ls -la /etc/rsyslog.d/ 2>/dev/null

# Check if utmp/wtmp/btmp were tampered with (login records)
last -F | head -20
stat /var/log/wtmp /var/log/btmp /var/run/utmp 2>/dev/null

# Check for log forwarding disabled
grep -r "@@\|@" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | grep -v "^#"
```

## Browser Forensics (Native Tools Only)

### Windows — Chrome

```powershell
# Chrome history (SQLite — readable with native tools via copy)
$histPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
if (Test-Path $histPath) {
  # Copy to avoid lock, then inspect
  Copy-Item $histPath "$env:TEMP\chrome-history-copy"
  Write-Host "Chrome history copied to $env:TEMP\chrome-history-copy (use sqlite3 to query)"
}

# Chrome downloads
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data\Default" -Filter "History*" | Select-Object FullName, LastWriteTime

# Chrome extensions (identify suspicious)
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions" -Directory | ForEach-Object {
  $manifest = Get-ChildItem $_.FullName -Recurse -Filter "manifest.json" | Select-Object -First 1
  if ($manifest) {
    $json = Get-Content $manifest.FullName -Raw | ConvertFrom-Json
    [PSCustomObject]@{ID=$_.Name; Name=$json.name; Version=$json.version; Permissions=($json.permissions -join ',')}
  }
}

# Chrome saved passwords location (encrypted — note existence)
Test-Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"

# Edge history (same Chromium structure)
$edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
Test-Path $edgePath
```

### Windows — Firefox

```powershell
# Firefox profiles and history
Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles\*" -Directory | ForEach-Object {
  Write-Host "=== Profile: $($_.Name) ==="
  Get-ChildItem $_.FullName -Filter "places.sqlite" | Select-Object FullName, LastWriteTime
  Get-ChildItem $_.FullName -Filter "downloads.sqlite" | Select-Object FullName, LastWriteTime
}

# Firefox extensions
Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles\*\extensions.json" -EA 0 | ForEach-Object {
  $json = Get-Content $_ -Raw | ConvertFrom-Json
  $json.addons | Select-Object id, name, version, active
}
```

### Linux

```bash
# Chrome history
find /home -path "*/.config/google-chrome/Default/History" -type f 2>/dev/null -exec ls -la {} \;
find /home -path "*/.config/chromium/Default/History" -type f 2>/dev/null -exec ls -la {} \;

# Firefox history
find /home -path "*/.mozilla/firefox/*/places.sqlite" -type f 2>/dev/null -exec ls -la {} \;

# Recent downloads (all browsers)
find /home/*/Downloads -type f -mtime -7 -ls 2>/dev/null | sort -k11

# Browser cache (may contain downloaded payloads)
find /home -path "*/.cache/google-chrome*" -name "*.tmp" -mtime -1 2>/dev/null | head -20
find /home -path "*/.cache/mozilla*" -name "*.tmp" -mtime -1 2>/dev/null | head -20

# Chromium-based browser database listing
find /home -name "Login Data" -o -name "Cookies" -o -name "Web Data" 2>/dev/null | grep -i "chrome\|chromium\|edge"
```

## Clipboard Investigation

### Windows

```powershell
# Current clipboard contents
Get-Clipboard
Get-Clipboard -Format Text
Get-Clipboard -Format FileDropList  # If files were copied

# Clipboard history (Win10 1809+ with clipboard history enabled)
# Stored in: %LOCALAPPDATA%\Microsoft\Windows\Clipboard
Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Windows\Clipboard" -Recurse -Force -EA 0 |
  Select-Object FullName, LastWriteTime, Length
```

### Linux

```bash
# X11 clipboard (if xclip/xsel available — common on desktop)
xclip -selection clipboard -o 2>/dev/null
xsel --clipboard --output 2>/dev/null

# Wayland clipboard
wl-paste 2>/dev/null

# Check clipboard managers for history
find /home -name "*clipman*" -o -name "*klipper*" -o -name "*parcellite*" 2>/dev/null
```

## PowerShell Transcription & Logging Forensics

```powershell
# Check if transcription is enabled and where transcripts are stored
$transcriptReg = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -EA 0
if ($transcriptReg) {
  Write-Host "Transcription enabled: $($transcriptReg.EnableTranscripting)"
  Write-Host "Output directory: $($transcriptReg.OutputDirectory)"
}

# Find PowerShell transcript files
Get-ChildItem -Path "C:\Users\*\Documents\PowerShell_transcript*" -Recurse -Force -EA 0 |
  Sort-Object LastWriteTime -Descending | Select-Object -First 20

# Check configured transcript directory
if ($transcriptReg.OutputDirectory) {
  Get-ChildItem $transcriptReg.OutputDirectory -Recurse -EA 0 | Sort-Object LastWriteTime -Descending | Select-Object -First 20
}

# Default transcript locations
Get-ChildItem "C:\Transcripts" -Recurse -Force -EA 0 | Select-Object -First 20

# ScriptBlock logging (Event ID 4104) — check if enabled
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -EA 0

# Module logging
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -EA 0

# Find recent Script Block logs
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 10 -EA 0 |
  Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value.Substring(0, [Math]::Min(200, $_.Properties[2].Value.Length))}}

# AMSI bypass detection — look for known bypass strings in ScriptBlock logs
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 500 -EA 0 |
  Where-Object {
    $_.Properties[2].Value -match 'AmsiUtils|amsiInitFailed|AmsiScanBuffer|amsi\.dll|Unmanaged|SetValue.*NonPublic'
  } | Select-Object TimeCreated, @{N='Snippet';E={$_.Properties[2].Value.Substring(0, [Math]::Min(300, $_.Properties[2].Value.Length))}}

# ETW tampering detection — check if event tracing was disabled
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Kernel-EventTracing/Admin'} -MaxEvents 20 -EA 0 |
  Select-Object TimeCreated, Id, Message
```

---

## Evidence Collection Safety Guidelines

### Principles

1. **Collect to external/network path** — Never write evidence to the system drive being investigated. Use a mounted USB, network share, or designated evidence partition.
2. **Hash everything** — Generate SHA256 hashes of all collected artifacts immediately after collection.
3. **Document chain of custody** — Record who collected what, when, and from where.
4. **Read-only first** — Do all investigation read-only before deciding what to collect.
5. **Minimize footprint** — Each command you run modifies timestamps and creates process artifacts.

### Evidence Output Paths

```powershell
# Windows — evidence to network share
$EvidenceDir = "\\forensics-share\cases\IR-001\$(hostname)"
New-Item -ItemType Directory -Path $EvidenceDir -Force

# Windows — evidence to USB
$EvidenceDir = "E:\evidence\$(hostname)_$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -ItemType Directory -Path $EvidenceDir -Force
```

```bash
# Linux — evidence to mounted share
EVIDENCE_DIR="/mnt/forensics/$(hostname)_$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

# Linux — evidence to USB
EVIDENCE_DIR="/media/usb/evidence/$(hostname)_$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"
```

### Hashing Collected Evidence

```powershell
# Hash all collected files
Get-ChildItem -Path $EvidenceDir -Recurse -File | ForEach-Object {
  [PSCustomObject]@{
    File = $_.FullName.Replace($EvidenceDir, ".")
    SHA256 = (Get-FileHash $_ -Algorithm SHA256).Hash
    Size = $_.Length
    Collected = Get-Date -Format "o"
  }
} | Export-Csv "$EvidenceDir\_hashes.csv" -NoTypeInformation
```

```bash
# Hash all collected files
find "$EVIDENCE_DIR" -type f -not -name "*.sha256" -exec sha256sum {} \; > "$EVIDENCE_DIR/collection-hashes.sha256"
echo "# Collected: $(date -Iseconds) by $(whoami)@$(hostname)" >> "$EVIDENCE_DIR/collection-hashes.sha256"
```

### OS Version Compatibility Notes

| Command/Feature | Minimum Version | Fallback |
|----------------|-----------------|----------|
| `Get-NetTCPConnection` | PowerShell 4.0+ (Win8.1+) | `netstat -ano` |
| `pktmon.exe` | Windows 10 1809+ | `netsh trace start` |
| `Get-FileHash` | PowerShell 4.0+ | `certutil -hashfile` |
| `Get-ComputerInfo` | PowerShell 5.1+ | `systeminfo` |
| `ss` | iproute2 (modern Linux) | `netstat -tunapl` |
| `journalctl` | systemd-based distros | `/var/log/syslog`, `/var/log/messages` |
| `ip` | iproute2 (modern Linux) | `ifconfig`, `route` |
| `getcap` | libcap2-bin | Manual `/proc/*/status` check |
| `ausearch` | auditd installed | `grep` through `/var/log/audit/audit.log` |
| `resolvectl` | systemd-resolved | `cat /etc/resolv.conf` |

# gather/windows/enum-browser-artifacts.ps1 — Enumerate browser artifacts and admin-console clues
# Requires: Standard user
# Read-only: YES
# MITRE ATT&CK: T1217 / evidence collection

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }

Sec 'OBJECTIVE'
'Collect browser profile artifacts, bookmarks, recent downloads, and enterprise/admin-console clues from common Windows browsers.'

Sec 'CHROME_ARTIFACTS'
Get-ChildItem 'C:\Users\*\AppData\Local\Google\Chrome\User Data\*' -Force | Where-Object {
    $_.Name -in 'History','Cookies','Login Data','Bookmarks','Preferences','Visited Links','Web Data'
} | Select-Object FullName, Length, LastWriteTime

Sec 'CHROME_BOOKMARK_AND_PREF_HINTS'
Get-ChildItem 'C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Bookmarks' -Force -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Output "--- $($_.FullName) ---"
    Select-String -Path $_.FullName -Pattern 'admin|console|vpn|rdp|jump|gateway|aws|azure|gcp|okta|entra|duo|jenkins|kibana|grafana|splunk|vcenter|prtg|nessus' | Select-Object -First 40 LineNumber, Line
}

Sec 'EDGE_ARTIFACTS'
Get-ChildItem 'C:\Users\*\AppData\Local\Microsoft\Edge\User Data\*' -Force | Where-Object {
    $_.Name -in 'History','Cookies','Login Data','Bookmarks','Preferences','Visited Links','Web Data'
} | Select-Object FullName, Length, LastWriteTime

Sec 'FIREFOX_ARTIFACTS'
Get-ChildItem 'C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*' -Force | Where-Object {
    $_.Name -in 'places.sqlite','cookies.sqlite','logins.json','key4.db','prefs.js','sessionstore.jsonlz4'
} | Select-Object FullName, Length, LastWriteTime

Sec 'IE_AND_LEGACY_ARTIFACTS'
Get-ChildItem 'C:\Users\*\Favorites' -Recurse -Force -ErrorAction SilentlyContinue | Select-Object FullName, LastWriteTime
Get-ItemProperty 'HKCU:\Software\Microsoft\Internet Explorer\TypedURLs' -ErrorAction SilentlyContinue | Select-Object *

Sec 'RECENT_DOWNLOAD_AND_RDP_HINTS'
Get-ChildItem 'C:\Users\*\Downloads' -Force -ErrorAction SilentlyContinue | Where-Object {
    $_.Extension -in '.rdp','.url','.lnk','.zip','.7z','.ps1','.bat','.vbs','.exe','.msi'
} | Select-Object FullName, Length, LastWriteTime | Sort-Object LastWriteTime -Descending

Sec 'BROWSER_ADMIN_CONSOLE_HINTS'
$paths = @(
    'C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Bookmarks',
    'C:\Users\*\AppData\Local\Microsoft\Edge\User Data\*\Bookmarks',
    'C:\Users\*\Favorites\*'
)
foreach ($p in $paths) {
    Get-ChildItem $p -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Select-String -Path $_.FullName -Pattern 'admin|console|vpn|rdp|jump|gateway|aws|azure|gcp|okta|entra|duo|jenkins|kibana|grafana|splunk|vcenter|prtg|nessus' -ErrorAction SilentlyContinue | Select-Object Path, LineNumber, Line
    }
}

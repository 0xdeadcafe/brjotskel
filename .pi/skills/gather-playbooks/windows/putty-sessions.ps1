# gather/windows/putty-sessions.ps1 — Enumerate PuTTY/Pageant session artifacts
# Requires: Registry read access to user hives
# Read-only: YES
# MITRE ATT&CK: T1552 / T1021

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }

Sec 'OBJECTIVE'
'Collect PuTTY saved sessions, stored SSH host keys, referenced key-file paths, and Pageant presence for pivot and credential triage.'

Sec 'PUTTY_SAVED_SESSIONS'
$base = 'HKCU:\Software\SimonTatham\PuTTY\Sessions'
if (Test-Path $base) {
    Get-ChildItem $base | ForEach-Object {
        $name = [uri]::UnescapeDataString($_.PSChildName)
        $props = Get-ItemProperty $_.PSPath
        [pscustomobject]@{
            Name = $name
            HostName = $props.HostName
            UserName = $props.UserName
            PortNumber = $props.PortNumber
            PublicKeyFile = $props.PublicKeyFile
            ProxyUsername = $props.ProxyUsername
            ProxyHost = $props.ProxyHost
            PortForwardings = $props.PortForwardings
        }
    } | Format-Table -AutoSize
} else {
    'No PuTTY saved sessions found in HKCU.'
}

Sec 'PUTTY_REFERENCED_KEY_FILES'
if (Test-Path $base) {
    Get-ChildItem $base | ForEach-Object {
        $name = [uri]::UnescapeDataString($_.PSChildName)
        $props = Get-ItemProperty $_.PSPath
        if ($props.PublicKeyFile) {
            [pscustomobject]@{
                Session = $name
                PublicKeyFile = $props.PublicKeyFile
                Exists = Test-Path $props.PublicKeyFile
            }
        }
    } | Format-Table -AutoSize
}

Sec 'PUTTY_STORED_HOST_KEYS'
$hostKeyBase = 'HKCU:\Software\SimonTatham\PuTTY\SshHostKeys'
if (Test-Path $hostKeyBase) {
    $item = Get-ItemProperty $hostKeyBase
    $item.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
        if ($_.Name -match '^(?<type>[-a-z0-9]+?)@(?<port>[0-9]+):(?<host>.+)$') {
            [pscustomobject]@{
                Host = $matches.host
                Port = $matches.port
                KeyType = $matches.type
                RegistryName = $_.Name
            }
        } else {
            [pscustomobject]@{
                Host = ''
                Port = ''
                KeyType = ''
                RegistryName = $_.Name
            }
        }
    } | Format-Table -AutoSize
} else {
    'No PuTTY stored SSH host keys found in HKCU.'
}

Sec 'PAGEANT_PRESENCE'
$pageant = Get-Process -Name pageant -ErrorAction SilentlyContinue
if ($pageant) {
    $pageant | Select-Object Name, Id, Path, StartTime
} else {
    'Pageant process not running.'
}

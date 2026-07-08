# gather/windows/enum-artifacts.ps1 — Hunt common attacker / remote-admin artifacts
# Requires: Standard user (some registry areas may need admin)
# Read-only: YES
# MITRE ATT&CK: artifact discovery / evidence collection
# Optional: set $ArtifactPackPath to a YAML pack when ConvertFrom-Yaml is available

param(
    [string]$ArtifactPackPath
)

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }

function Get-DefaultArtifactPack {
    return @{
        files = @(
            'C:\Windows\Temp\*.ps1',
            'C:\Windows\Temp\*.bat',
            'C:\Windows\Temp\*.vbs',
            'C:\Users\*\AppData\Local\Temp\*.ps1',
            'C:\Users\*\AppData\Local\Temp\*.bat',
            'C:\Users\*\AppData\Local\Temp\*.vbs',
            'C:\Users\*\Downloads\*.rdp',
            'C:\Users\*\Downloads\*.ppk',
            'C:\Users\*\.ssh\config',
            'C:\Users\*\.ssh\known_hosts',
            'C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt',
            'C:\inetpub\wwwroot\*.aspx',
            'C:\inetpub\wwwroot\*.ashx',
            'C:\ProgramData\*.exe',
            'C:\ProgramData\*.dll',
            'C:\Users\Public\*.exe',
            'C:\Users\Public\*.dll',
            'C:\Windows\Temp\*plink*',
            'C:\Windows\Temp\*chisel*',
            'C:\Windows\Temp\*ngrok*',
            'C:\Users\*\AppData\Local\Temp\*plink*',
            'C:\Users\*\AppData\Local\Temp\*chisel*',
            'C:\Users\*\AppData\Local\Temp\*ngrok*'
        )
        registry = @(
            'HKCU:\Software\SimonTatham\PuTTY\Sessions',
            'HKCU:\Software\SimonTatham\PuTTY\SshHostKeys',
            'HKCU:\Software\Microsoft\Terminal Server Client\Servers',
            'HKCU:\Software\Microsoft\Terminal Server Client\Default',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths',
            'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes'
        )
    }
}

function Get-ArtifactPack {
    if ($ArtifactPackPath -and (Test-Path $ArtifactPackPath) -and (Get-Command ConvertFrom-Yaml -ErrorAction SilentlyContinue)) {
        try {
            return Get-Content $ArtifactPackPath -Raw | ConvertFrom-Yaml
        } catch {
            return Get-DefaultArtifactPack
        }
    }
    return Get-DefaultArtifactPack
}

$pack = Get-ArtifactPack

Sec 'OBJECTIVE'
'Check high-signal file-system and registry locations for common attacker tooling, remote-admin traces, and script execution artifacts.'

Sec 'ARTIFACT_PACK_INFO'
if ($ArtifactPackPath) {
    Write-Output "ArtifactPackPath: $ArtifactPackPath"
    Write-Output "ConvertFrom-Yaml available: $([bool](Get-Command ConvertFrom-Yaml -ErrorAction SilentlyContinue))"
} else {
    Write-Output 'ArtifactPackPath: (default built-in pack)'
}

Sec 'FILES_FROM_PACK'
foreach ($pattern in ($pack.files | Select-Object -Unique)) {
    Write-Output "--- pattern: $pattern ---"
    Get-ChildItem $pattern -Force -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime
}

Sec 'REGISTRY_FROM_PACK'
foreach ($path in ($pack.registry | Select-Object -Unique)) {
    if (Test-Path $path) {
        Write-Output "--- $path ---"
        Get-ItemProperty $path | Select-Object *
    }
}

Sec 'SERVICES_SUSPICIOUS_PATHS'
Get-CimInstance Win32_Service | Where-Object {
    $_.PathName -and $_.PathName -match 'Temp|AppData|ProgramData|Users\\Public'
} | Select-Object Name, State, StartMode, PathName

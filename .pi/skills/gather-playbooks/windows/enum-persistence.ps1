# gather/windows/enum-persistence.ps1 — Detect persistence mechanisms
# Requires: Admin for full coverage
# Read-only: YES
# MITRE ATT&CK: T1547 (Boot/Logon), T1053 (Scheduled Task), T1543 (Service), T1546 (Event)

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }
function Run($c) { Write-Output "PS> $c"; Invoke-Expression $c }

Sec 'RUN_KEYS'
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($key in $runKeys) {
    $items = Get-ItemProperty $key -ErrorAction SilentlyContinue
    if ($items) {
        Write-Output "--- $key ---"
        $items.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object { Write-Output "  $($_.Name) = $($_.Value)" }
    }
}

Sec 'STARTUP_FOLDERS'
$startupPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($p in $startupPaths) {
    if (Test-Path $p) {
        $files = Get-ChildItem $p -Force 2>$null
        if ($files) { Write-Output "--- $p ---"; $files | Format-Table Name, Length, LastWriteTime }
    }
}

Sec 'SCHEDULED_TASKS_NON_MICROSOFT'
Run 'Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch "\\Microsoft\\\\" } | ForEach-Object { $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue; $actions = $_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }; Write-Output "Task: $($_.TaskName)"; Write-Output "  Path: $($_.TaskPath)"; Write-Output "  State: $($_.State)"; Write-Output "  Actions: $($actions -join \"; \")"; Write-Output "  RunAs: $($_.Principal.UserId)"; Write-Output "  LastRun: $($info.LastRunTime)"; Write-Output "" }'

Sec 'SERVICES_UNUSUAL_PATHS'
Run 'Get-CimInstance Win32_Service | Where-Object { $_.PathName -and $_.PathName -notmatch "System32|SysWOW64|Program Files|Microsoft" } | Format-Table Name, State, StartMode, @{N="Path";E={$_.PathName}} -AutoSize'

Sec 'WMI_EVENT_SUBSCRIPTIONS'
Run 'Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | ForEach-Object { Write-Output "[Filter] $($_.Name): $($_.Query)" }'
Run 'Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer | ForEach-Object { Write-Output "[Consumer] $($_.Name): $($_.CommandLineTemplate)" }'
Run 'Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer | ForEach-Object { Write-Output "[ScriptConsumer] $($_.Name): $($_.ScriptText)" }'

Sec 'BITS_JOBS'
Run 'Get-BitsTransfer -AllUsers | Format-Table DisplayName, TransferType, JobState, @{N="Files";E={$_.FileList.RemoteName}}'

Sec 'COM_HIJACKS'
$comHijack = Get-ChildItem "HKCU:\SOFTWARE\Classes\CLSID" -ErrorAction SilentlyContinue | ForEach-Object {
    Get-ItemProperty "$($_.PSPath)\InprocServer32" -ErrorAction SilentlyContinue
} | Where-Object { $_."(default)" }
if ($comHijack) { $comHijack | Select-Object "(default)", PSPath | Format-Table }

Sec 'IMAGE_FILE_EXECUTION_OPTIONS'
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue | ForEach-Object {
    $dbg = (Get-ItemProperty $_.PSPath -Name "Debugger" -ErrorAction SilentlyContinue).Debugger
    if ($dbg) { Write-Output "$($_.PSChildName): $dbg" }
}

Sec 'PRINT_MONITOR_DLLS'
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors\*" -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.Driver) { Write-Output "$($_.PSChildName): $($_.Driver)" }
}

Sec 'NETSH_HELPER_DLLS'
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NetSh" -ErrorAction SilentlyContinue | ForEach-Object {
    $_.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object { Write-Output "  $($_.Name) = $($_.Value)" }
}

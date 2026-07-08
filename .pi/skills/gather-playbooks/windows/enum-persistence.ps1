# gather/windows/enum-persistence.ps1 — Detect persistence mechanisms
# Requires: Admin for full coverage
# Read-only: YES
# MITRE ATT&CK: T1547 (Boot/Logon), T1053 (Scheduled Task), T1543 (Service), T1546 (Event)

Write-Output "=== RUN KEYS ==="
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

Write-Output ""
Write-Output "=== STARTUP FOLDERS ==="
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

Write-Output ""
Write-Output "=== SCHEDULED TASKS (detailed, non-Microsoft) ==="
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.TaskPath -notmatch "\\Microsoft\\"
} | ForEach-Object {
    $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
    $actions = $_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }
    Write-Output "Task: $($_.TaskName)"
    Write-Output "  Path: $($_.TaskPath)"
    Write-Output "  State: $($_.State)"
    Write-Output "  Actions: $($actions -join '; ')"
    Write-Output "  RunAs: $($_.Principal.UserId)"
    Write-Output "  LastRun: $($info.LastRunTime)"
    Write-Output ""
}

Write-Output ""
Write-Output "=== SERVICES (unusual paths) ==="
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
    $_.PathName -and $_.PathName -notmatch "System32|SysWOW64|Program Files|Microsoft"
} | Format-Table Name, State, StartMode, @{N="Path";E={$_.PathName}} -AutoSize

Write-Output ""
Write-Output "=== WMI EVENT SUBSCRIPTIONS ==="
Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Output "[Filter] $($_.Name): $($_.Query)"
}
Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Output "[Consumer] $($_.Name): $($_.CommandLineTemplate)"
}
Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Output "[ScriptConsumer] $($_.Name): $($_.ScriptText)"
}

Write-Output ""
Write-Output "=== BITS JOBS ==="
Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | Format-Table DisplayName, TransferType, JobState, @{N="Files";E={$_.FileList.RemoteName}}

Write-Output ""
Write-Output "=== COM HIJACKS (InprocServer32 in HKCU) ==="
$comHijack = Get-ChildItem "HKCU:\SOFTWARE\Classes\CLSID" -ErrorAction SilentlyContinue | ForEach-Object {
    Get-ItemProperty "$($_.PSPath)\InprocServer32" -ErrorAction SilentlyContinue
} | Where-Object { $_."(default)" }
if ($comHijack) { $comHijack | Select-Object "(default)", PSPath | Format-Table }

Write-Output ""
Write-Output "=== IMAGE FILE EXECUTION OPTIONS (debugger) ==="
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue | ForEach-Object {
    $dbg = (Get-ItemProperty $_.PSPath -Name "Debugger" -ErrorAction SilentlyContinue).Debugger
    if ($dbg) { Write-Output "$($_.PSChildName): $dbg" }
}

Write-Output ""
Write-Output "=== PRINT MONITOR DLLs ==="
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors\*" -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.Driver) { Write-Output "$($_.PSChildName): $($_.Driver)" }
}

Write-Output ""
Write-Output "=== NETSH HELPER DLLs ==="
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NetSh" -ErrorAction SilentlyContinue | ForEach-Object {
    $_.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object { Write-Output "  $($_.Name) = $($_.Value)" }
}

# eradication/windows/remove-scheduled-task.ps1 — Evidence-backed scheduled task removal
# Requires: Admin
# State-changing: YES — disables and unregisters the task
# Pattern: EVIDENCE → DISABLE → UNREGISTER → VERIFY
#
# Parameters:
#   $TaskName   — scheduled task name (required)
#   $TaskPath   — task folder path, e.g. "\" or "\Microsoft\Windows\" (default: search all)
#
# Usage:
#   $TaskName = "WindowsUpdate"; <paste>
#   $TaskName = "SvcHost32"; $TaskPath = "\"; <paste>
#
# ⚠️  Containment first. Run collect-evidence.ps1 before this.

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }

if (-not $TaskName) {
  Write-Error "Set `$TaskName = '<task name>' before running"
  exit 1
}

# Find the task
$task = if ($TaskPath) {
  Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
} else {
  Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
}

if (-not $task) {
  Write-Error "Scheduled task '$TaskName' not found"
  exit 1
}

Sec 'EVIDENCE — TASK STATE BEFORE REMOVAL'
Write-Output "Timestamp: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
Write-Output "Task: $($task.TaskPath)$($task.TaskName)"

Write-Output "`n--- Task definition ---"
$task | Format-List *

Write-Output "`n--- Task info ---"
$task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue | Format-List

Write-Output "`n--- Triggers ---"
$task.Triggers | Format-List

Write-Output "`n--- Actions ---"
$task.Actions | ForEach-Object { Write-Output "  Execute: $($_.Execute)  Args: $($_.Arguments)  WorkDir: $($_.WorkingDirectory)" }

Write-Output "`n--- Run-as principal ---"
$task.Principal | Format-List

# Hash the action binary
$task.Actions | ForEach-Object {
  $bin = $_.Execute -replace '"','' -replace "'",''; $bin = $bin.Trim()
  if ($bin -and (Test-Path $bin -PathType Leaf)) {
    Write-Output "`n--- Action binary hash ---"
    (Get-FileHash $bin -Algorithm SHA256 -EA SilentlyContinue).Hash + "  $bin"
  }
}

Sec 'SAVE EVIDENCE'
$evidencePath = "$env:TEMP\evidence-task-$($task.TaskName -replace '[\\/:*?"<>|]','_')-$((Get-Date).ToString('yyyyMMddTHHmmss')).xml"
$task | Export-Clixml -Path $evidencePath -ErrorAction SilentlyContinue
Write-Output "[OK] Task definition exported to: $evidencePath"
Write-Output "     Pull this to: workspace/evidence/<host>/task-$($task.TaskName).xml"

Sec 'DISABLE THEN UNREGISTER'
Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
Write-Output "[OK] Task disabled"

Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
Write-Output "[OK] Task unregistered: $($task.TaskPath)$($task.TaskName)"

Sec 'VERIFY — TASK GONE'
$check = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($check) {
  Write-Output "[FAIL] Task still exists: $($check.TaskPath)$($check.TaskName)"
} else {
  Write-Output "[OK] Task '$TaskName' is gone"
}

Write-Output "`nWait 60s and verify task did not recreate."
Write-Output "Re-check: Get-ScheduledTask -TaskName '$TaskName'"

Sec 'INTEL TIMELINE SNIPPET'
Write-Output @"

intel_timeline(action="add", entry_type="eradication", entry_action="eradicated",
  target="<HOST_ID>",
  summary="<HOST_ID>: scheduled task '$($task.TaskName)' removed at $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))")
"@

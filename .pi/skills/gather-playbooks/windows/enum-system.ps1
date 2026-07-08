# gather/windows/enum-system.ps1 — System and user enumeration
# Requires: Standard user (admin for full coverage)
# Read-only: YES
# MITRE ATT&CK: T1082 — System Information Discovery

Write-Output "=== SYSTEM INFO ==="
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
Write-Output "Hostname: $env:COMPUTERNAME"
Write-Output "Domain: $env:USERDOMAIN / $env:USERDNSDOMAIN"
Write-Output "OS: $($os.Caption) $($os.Version) Build $($os.BuildNumber)"
Write-Output "Arch: $env:PROCESSOR_ARCHITECTURE"
Write-Output "Boot: $($os.LastBootUpTime)"

Write-Output ""
Write-Output "=== CURRENT USER ==="
Write-Output "User: $env:USERNAME"
Write-Output "Domain: $env:USERDOMAIN"
whoami /priv 2>$null
whoami /groups 2>$null | Select-Object -First 20

Write-Output ""
Write-Output "=== LOCAL USERS ==="
Get-LocalUser -ErrorAction SilentlyContinue | Format-Table Name, Enabled, LastLogon, PasswordLastSet

Write-Output ""
Write-Output "=== LOCAL GROUPS ==="
Get-LocalGroup -ErrorAction SilentlyContinue | ForEach-Object {
    $members = Get-LocalGroupMember $_.Name -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }
    if ($members) { Write-Output "$($_.Name): $($members -join ', ')" }
}

Write-Output ""
Write-Output "=== LOGGED ON USERS ==="
query user 2>$null

Write-Output ""
Write-Output "=== SERVICES (non-Microsoft) ==="
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
    $_.PathName -and $_.PathName -notmatch "Windows\\System32|Microsoft|svchost"
} | Format-Table Name, State, StartMode, @{N="Path";E={$_.PathName}} -AutoSize | Out-String -Width 200

Write-Output ""
Write-Output "=== SCHEDULED TASKS (non-Microsoft) ==="
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.TaskPath -notmatch "\\Microsoft\\" -and $_.State -ne "Disabled"
} | Format-Table TaskName, TaskPath, State -AutoSize

Write-Output ""
Write-Output "=== INSTALLED SOFTWARE ==="
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName } |
    Sort-Object DisplayName |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Format-Table -AutoSize | Out-String -Width 200 | Select-Object -First 40

Write-Output ""
Write-Output "=== POWERSHELL VERSION ==="
$PSVersionTable | Format-Table -AutoSize

Write-Output ""
Write-Output "=== .NET VERSIONS ==="
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP" -Recurse -ErrorAction SilentlyContinue |
    Get-ItemProperty -Name Version -ErrorAction SilentlyContinue |
    Select-Object PSChildName, Version | Format-Table

Write-Output ""
Write-Output "=== RECENT INSTALLS (last 7 days) ==="
Get-WinEvent -FilterHashtable @{LogName='Application'; ID=11707; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 10 -ErrorAction SilentlyContinue |
    ForEach-Object { Write-Output "$($_.TimeCreated): $($_.Message)" }

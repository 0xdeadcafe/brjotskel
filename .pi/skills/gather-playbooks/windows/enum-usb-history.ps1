# gather/windows/enum-usb-history.ps1 — Enumerate USB storage history
# Requires: Registry read access
# Read-only: YES
# MITRE ATT&CK: T1091 / evidence triage

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }

Sec 'OBJECTIVE'
'Collect USB storage device history to identify removable-media usage and potentially relevant operator or exfiltration artifacts.'

Sec 'USBSTOR_DEVICES'
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' | Select-Object FriendlyName, Mfg, Service, ContainerID, @{N='PSPath';E={$_.PSPath}}

Sec 'USB_CLASS_DEVICES'
Get-PnpDevice -Class USB -PresentOnly | Select-Object Status, Class, FriendlyName, InstanceId

Sec 'MOUNTED_DRIVES'
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\*' | Select-Object PSChildName, PSPath

Sec 'REMOVABLE_VOLUMES'
Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -in 2,5 } | Select-Object DeviceID, VolumeName, Description, ProviderName

# eradication/windows/remove-wmi-subscription.ps1 — Remove WMI event subscription
# Requires: Admin
# State-changing: YES — removes Filter, Consumer, and Binding objects
# Pattern: EVIDENCE → REMOVE ALL THREE OBJECTS → VERIFY
#
# WMI persistence = three objects that must ALL be removed:
#   __EventFilter        — the trigger condition
#   CommandLineEventConsumer / ActiveScriptEventConsumer — the action
#   __FilterToConsumerBinding — the link between them
#
# Parameters:
#   $SubscriptionName  — name used across Filter, Consumer, and Binding objects
#
# Usage:
#   $SubscriptionName = "WindowsUpdater"; <paste>
#
# ⚠️  Containment first. Confirm the subscription name matches the attacker's object.
# ⚠️  If Filter/Consumer/Binding use different names, run sections manually.

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }

if (-not $SubscriptionName) {
  Write-Error "Set `$SubscriptionName = '<name>' before running"
  exit 1
}

Sec 'EVIDENCE — WMI SUBSCRIPTION STATE BEFORE REMOVAL'
Write-Output "Timestamp:         $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
Write-Output "Subscription name: $SubscriptionName"

$filter   = Get-CimInstance -Namespace root/subscription -ClassName __EventFilter |
              Where-Object { $_.Name -eq $SubscriptionName }
$consumer = Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer |
              Where-Object { $_.Name -eq $SubscriptionName }
$consumerScript = Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer |
              Where-Object { $_.Name -eq $SubscriptionName }
$binding  = Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding |
              Where-Object { $_.Filter.Name -eq $SubscriptionName -or $_.Consumer.Name -eq $SubscriptionName }

Write-Output "`n--- EventFilter ---"
if ($filter) { $filter | Format-List Name, Query, QueryLanguage, EventNameSpace }
else { Write-Output "(not found)" }

Write-Output "`n--- CommandLineEventConsumer ---"
if ($consumer) { $consumer | Format-List Name, CommandLineTemplate, ExecutablePath }
else { Write-Output "(not found)" }

Write-Output "`n--- ActiveScriptEventConsumer ---"
if ($consumerScript) { $consumerScript | Format-List Name, ScriptText, ScriptingEngine }
else { Write-Output "(not found)" }

Write-Output "`n--- FilterToConsumerBinding ---"
if ($binding) { $binding | Format-List * }
else { Write-Output "(not found)" }

# Hash any referenced binary
if ($consumer?.ExecutablePath -and (Test-Path $consumer.ExecutablePath)) {
  Write-Output "`n--- Consumer binary hash ---"
  (Get-FileHash $consumer.ExecutablePath -Algorithm SHA256 -EA SilentlyContinue).Hash + "  $($consumer.ExecutablePath)"
}

Sec 'SAVE EVIDENCE'
$ts = (Get-Date).ToString('yyyyMMddTHHmmss')
$name = $SubscriptionName -replace '[\\/:*?"<>|]','_'
if ($filter)         { $filter         | Export-Clixml "$env:TEMP\evidence-wmi-filter-$name-$ts.xml" }
if ($consumer)       { $consumer       | Export-Clixml "$env:TEMP\evidence-wmi-consumer-$name-$ts.xml" }
if ($consumerScript) { $consumerScript | Export-Clixml "$env:TEMP\evidence-wmi-scriptconsumer-$name-$ts.xml" }
if ($binding)        { $binding        | Export-Clixml "$env:TEMP\evidence-wmi-binding-$name-$ts.xml" }
Write-Output "[OK] Evidence exported to $env:TEMP\evidence-wmi-*-$name-$ts.xml"
Write-Output "     Pull to: workspace/evidence/<host>/wmi-$SubscriptionName/"

Sec 'REMOVE — BINDING FIRST, THEN CONSUMER, THEN FILTER'
# Order matters: remove binding first, or re-trigger can fire during removal

Write-Output "--- Remove FilterToConsumerBinding ---"
if ($binding) {
  $binding | Remove-CimInstance -ErrorAction SilentlyContinue
  Write-Output "[OK] FilterToConsumerBinding removed"
} else { Write-Output "(not found — skipped)" }

Write-Output "`n--- Remove Consumer ---"
if ($consumer) {
  $consumer | Remove-CimInstance -ErrorAction SilentlyContinue
  Write-Output "[OK] CommandLineEventConsumer removed"
}
if ($consumerScript) {
  $consumerScript | Remove-CimInstance -ErrorAction SilentlyContinue
  Write-Output "[OK] ActiveScriptEventConsumer removed"
}
if (-not $consumer -and -not $consumerScript) { Write-Output "(not found — skipped)" }

Write-Output "`n--- Remove EventFilter ---"
if ($filter) {
  $filter | Remove-CimInstance -ErrorAction SilentlyContinue
  Write-Output "[OK] EventFilter removed"
} else { Write-Output "(not found — skipped)" }

Sec 'VERIFY — ALL THREE OBJECTS GONE'
$checkFilter   = Get-CimInstance -Namespace root/subscription -ClassName __EventFilter |
                   Where-Object { $_.Name -eq $SubscriptionName }
$checkConsumer = Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer |
                   Where-Object { $_.Name -eq $SubscriptionName }
$checkScript   = Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer |
                   Where-Object { $_.Name -eq $SubscriptionName }
$checkBinding  = Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding |
                   Where-Object { $_.Filter.Name -eq $SubscriptionName -or $_.Consumer.Name -eq $SubscriptionName }

if ($checkFilter)   { Write-Output "[FAIL] EventFilter still present" }
else                { Write-Output "[OK] EventFilter gone" }

if ($checkConsumer -or $checkScript) { Write-Output "[FAIL] Consumer still present" }
else                                 { Write-Output "[OK] Consumer gone" }

if ($checkBinding)  { Write-Output "[FAIL] FilterToConsumerBinding still present" }
else                { Write-Output "[OK] FilterToConsumerBinding gone" }

Sec 'INTEL TIMELINE SNIPPET'
Write-Output @"

intel_timeline(action="add", entry_type="eradication", entry_action="eradicated",
  target="<HOST_ID>",
  summary="<HOST_ID>: WMI subscription '$SubscriptionName' (Filter+Consumer+Binding) removed at $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))")
"@

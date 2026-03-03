<#
.SYNOPSIS
    Invoke-MDE-DeviceLifecycle.ps1 v3.0.0
    MDE Device Governance — Complete Lifecycle Engine

.DESCRIPTION
    ENTERPRISE LIFECYCLE ENGINE for Microsoft Defender for Endpoint.

    Classifies ALL Windows Server + Linux devices in MDE with EXACTLY ONE managed tag
    per device, following a strict 5-priority decision tree:

    ════════════════════════════════════════════════════════════════════
    CLASSIFICATION PRIORITIES (first match wins):
    ════════════════════════════════════════════════════════════════════

    P1 — DUPLICADA_EXCLUIR
        Same hostname, multiple machineIds → oldest flagged.
        Source: re-imaging, re-onboarding. Offboard candidate.
        Exception: VMSS patterns (_0, _1, _000000) are intentional duplicates → ignored.

    P2 — EFEMERO
        Device lifespan ≤ horasEfemero (default 48h) AND Inactive/NoSensorData.
        Typical: VMSS scale-in, CI/CD runners, short-lived containers.
        EXCEPTION: If VM still exists in Azure (resourceId mapped to a known subscription)
        → classified as P5 subscription tag instead of EFEMERO.

    P3 — INATIVO_40D
        No communication for > diasInativo40d (default 40) days.
        Likely decommissioned. Investigate before offboarding.

    P4 — INATIVO_7D
        No communication for > diasInativo7d (default 7) and ≤ diasInativo40d days.
        May be maintenance, vacation, network issue. Monitor.

    P5 — {SUBSCRIPTION_NAME}
        Active device (last report < diasInativo7d days ago) with known Azure subscription.
        This is the PRIMARY tag for Device Group segmentation by subscription.
        Tag format: UPPERCASE subscription name, spaces→underscore, special chars stripped.

    FALLBACK — No managed tag applied
        Active server with no Azure subscription (on-prem without Arc). Script ignores it.

    ════════════════════════════════════════════════════════════════════
    KEY GUARANTEES:
    ════════════════════════════════════════════════════════════════════
    ✔ EXACTLY ONE managed tag per device (previous managed tags are removed first)
    ✔ Non-managed tags (GPO, manual, other scripts) are NEVER touched
    ✔ Legacy tags from older script versions are cleaned automatically
    ✔ reportOnly=$true is the DEFAULT (safe dry-run)
    ✔ Bulk API with graceful fallback to individual endpoints (403 detection)
    ✔ OAuth2 token auto-refresh (401) + rate-limit backoff (429, 180s)

    ════════════════════════════════════════════════════════════════════
    SUBSCRIPTION DISCOVERY — 4-level cascade:
    ════════════════════════════════════════════════════════════════════
    Level 1: config/subscription_mapping.csv (explicit, fastest)
    Level 2: Azure Resource Manager API (requires App Reg Reader role on subscriptions)
    Level 3: Azure CLI (az account list — requires prior az login)
    Level 4: MDE device vmMetadata (zero extra permissions, enriched via ARM if available)

    ════════════════════════════════════════════════════════════════════
    AZURE AUTOMATION NATIVE (v3.0 NEW):
    ════════════════════════════════════════════════════════════════════
    When -UseAzureAutomation $true:
    - Reads tenantId/appId/appSecret from AA Automation Variables
    - Can use Managed Identity for ARM token (-UseManagedIdentity $true)
    - No secrets in files or command line

    ════════════════════════════════════════════════════════════════════
    SUGGESTED DEVICE GROUPS (create manually in security.microsoft.com):
    ════════════════════════════════════════════════════════════════════
    | Device Group              | Tag filter             | Automation Level      |
    |---------------------------|------------------------|-----------------------|
    | Servers-{Subscription}    | {SUBSCRIPTION_NAME}    | Full / Semi-automated |
    | Servers-Inativos-7d       | INATIVO_7D             | Semi-automated        |
    | Servers-Inativos-40d      | INATIVO_40D            | No automated response |
    | Servers-Efemeros          | EFEMERO                | No automated response |
    | Servers-Duplicadas        | DUPLICADA_EXCLUIR      | No automated response |

.PARAMETER tenantId
    Azure Tenant ID. Optional when UseAzureAutomation=$true.

.PARAMETER appId
    MDE App Registration Client ID. Optional when UseAzureAutomation=$true.

.PARAMETER appSecret
    MDE App Registration Client Secret. Optional when UseAzureAutomation=$true.

.PARAMETER subscriptionMappingPath
    Path to CSV with subscriptionId;subscriptionName pairs.
    Default: ..\config\subscription_mapping.csv (relative to script).
    Optional when autoDiscoverSubscriptions=$true.

.PARAMETER autoDiscoverSubscriptions
    $true = cascades through 4 discovery levels automatically. Default: $true.

.PARAMETER saveDiscoveredCsv
    $true = persists discovered subscriptions to CSV for audit + next-run reuse. Default: $true.

.PARAMETER excludeSubscriptions
    Array of subscriptionIds to skip. Example: @('sub-id-a','sub-id-b').

.PARAMETER reportOnly
    $true = dry-run, no changes. $false = applies tags to MDE. DEFAULT: $true (SAFE).

.PARAMETER diasInativo7d
    Days without report to classify as INATIVO_7D. Default: 7.
    (v3.0: was hardcoded in v2.2)

.PARAMETER diasInativo40d
    Days without report to classify as INATIVO_40D. Default: 40.
    (v3.0: was hardcoded in v2.2)

.PARAMETER horasEfemero
    Max device lifespan in hours to be considered ephemeral. Default: 48.
    (v3.0: was hardcoded in v2.2)

.PARAMETER UseAzureAutomation
    When $true, reads credentials from Azure Automation Variables instead of parameters.
    Variable names configured via -AaVarTenantId, -AaVarAppId, -AaVarAppSecret.
    Default: $false.

.PARAMETER AaVarTenantId
    Azure Automation Variable name for TenantId. Default: 'MDEGovernance-TenantId'.

.PARAMETER AaVarAppId
    Azure Automation Variable name for AppId. Default: 'MDEGovernance-AppId'.

.PARAMETER AaVarAppSecret
    Azure Automation Variable name for AppSecret. Default: 'MDEGovernance-AppSecret'.

.PARAMETER UseManagedIdentity
    When $true, uses Azure IMDS endpoint to obtain ARM token (no Client Secret needed for
    subscription discovery). Requires script execution on Azure VM or Azure Automation
    with System-assigned Managed Identity. Default: $false.

.PARAMETER OffboardCandidateReportPath
    Optional path for a separate CSV containing only INATIVO_40D + DUPLICADA_EXCLUIR devices.
    Used to drive decommission workflows. Leave empty to skip.

.PARAMETER NotifyWebhookUrl
    Optional: HTTP POST a JSON summary to this URL after execution.
    Compatible with: Microsoft Teams webhooks, Slack, Logic Apps, Power Automate.

.EXAMPLE
    # Dry-run with auto-discovery (safest, first run)
    .\Invoke-MDE-DeviceLifecycle.ps1 -tenantId "..." -appId "..." -appSecret "..."

.EXAMPLE
    # Apply tags in production
    .\Invoke-MDE-DeviceLifecycle.ps1 -tenantId "..." -appId "..." -appSecret "..." -reportOnly $false

.EXAMPLE
    # Custom thresholds (financial sector SLA)
    .\Invoke-MDE-DeviceLifecycle.ps1 -tenantId "..." -appId "..." -appSecret "..." `
        -diasInativo7d 3 -diasInativo40d 15 -horasEfemero 24 -reportOnly $false

.EXAMPLE
    # Azure Automation / Runbook with Managed Identity for ARM, AA Variables for MDE creds
    .\Invoke-MDE-DeviceLifecycle.ps1 -UseAzureAutomation $true -UseManagedIdentity $true

.EXAMPLE
    # With offboard candidates export and webhook notification
    .\Invoke-MDE-DeviceLifecycle.ps1 -tenantId "..." -appId "..." -appSecret "..." `
        -reportOnly $false `
        -OffboardCandidateReportPath "C:\Reports\offboard-$(Get-Date -f yyyyMMdd).csv" `
        -NotifyWebhookUrl "https://your-teams-webhook-url"

.NOTES
    Version:  3.0.0
    Date:     2026-03-02
    Author:   Rafael França — github.com/rfranca777
    Project:  github.com/rfranca777/MDE-DeviceGovernance
    License:  MIT
    
    Requires:
        App Registration:  Machine.ReadWrite.All (mandatory)
        Subscription Reader: Optional — improves subscription name resolution (Level 2 discovery)
        Azure CLI:           Optional — Level 3 discovery fallback
        PowerShell:          5.1+ (Windows PowerShell or PowerShell 7+)
    
    Backward Compatible: All v2.2 parameters work unchanged.
    
    v3.0 Changes over v2.2:
        + Configurable thresholds (-diasInativo7d, -diasInativo40d, -horasEfemero)
        + Azure Automation native support (-UseAzureAutomation, -AaVar*)
        + Managed Identity ARM token (-UseManagedIdentity)
        + Offboard candidates export (-OffboardCandidateReportPath)
        + Webhook notification (-NotifyWebhookUrl)
        + Enhanced summary with action recommendations
        + Default CSV path relative to script (auto-resolved)
#>

param (
    [Parameter(Mandatory = $false)] [string]   $tenantId,
    [Parameter(Mandatory = $false)] [string]   $appId,
    [Parameter(Mandatory = $false)] [string]   $appSecret,
    [Parameter(Mandatory = $false)] [string]   $subscriptionMappingPath = "",
    [Parameter(Mandatory = $false)] [bool]     $autoDiscoverSubscriptions = $true,
    [Parameter(Mandatory = $false)] [bool]     $saveDiscoveredCsv = $true,
    [Parameter(Mandatory = $false)] [string[]] $excludeSubscriptions = @(),
    [Parameter(Mandatory = $false)] [bool]     $reportOnly = $true,
    # v3.0 — configurable thresholds
    [Parameter(Mandatory = $false)] [int]      $diasInativo7d  = 7,
    [Parameter(Mandatory = $false)] [int]      $diasInativo40d = 40,
    [Parameter(Mandatory = $false)] [int]      $horasEfemero   = 48,
    # v3.0 — Azure Automation native
    [Parameter(Mandatory = $false)] [bool]     $UseAzureAutomation = $false,
    [Parameter(Mandatory = $false)] [string]   $AaVarTenantId  = "MDEGovernance-TenantId",
    [Parameter(Mandatory = $false)] [string]   $AaVarAppId     = "MDEGovernance-AppId",
    [Parameter(Mandatory = $false)] [string]   $AaVarAppSecret = "MDEGovernance-AppSecret",
    # v3.0 — Managed Identity for ARM
    [Parameter(Mandatory = $false)] [bool]     $UseManagedIdentity = $false,
    # v3.0 — offboard candidates + webhook
    [Parameter(Mandatory = $false)] [string]   $OffboardCandidateReportPath = "",
    [Parameter(Mandatory = $false)] [string]   $NotifyWebhookUrl = ""
)

# ============================================================================
# CONFIGURATION — globals
# ============================================================================
$ErrorActionPreference = "Continue"
$script:Version    = "3.0.0"
$script:RunDate    = Get-Date -Format "yyyy-MM-dd_HH-mm"
$script:ScriptRoot = $PSScriptRoot

# Resolve default CSV path relative to script location
if ([string]::IsNullOrWhiteSpace($subscriptionMappingPath)) {
    $subscriptionMappingPath = Join-Path $script:ScriptRoot "..\config\subscription_mapping.csv"
    $subscriptionMappingPath = [System.IO.Path]::GetFullPath($subscriptionMappingPath)
}

$script:ReportPath  = Join-Path $script:ScriptRoot "DeviceLifecycle-Report-$($script:RunDate).csv"
$script:LogPath     = Join-Path $script:ScriptRoot "DeviceLifecycle-Log-$($script:RunDate).log"

# Thresholds (from parameters — configurable)
$script:Thresholds = @{
    DiasInativo7d  = $diasInativo7d
    DiasInativo40d = $diasInativo40d
    HorasEfemero   = $horasEfemero
}

# Tags managed by this script (COMPLETE list — used for cleanup)
$script:MANAGED_TAGS = [System.Collections.Generic.List[string]]::new()
$script:MANAGED_TAGS.Add("DUPLICADA_EXCLUIR")
$script:MANAGED_TAGS.Add("EFEMERO")
$script:MANAGED_TAGS.Add("INATIVO_40D")
$script:MANAGED_TAGS.Add("INATIVO_7D")
# Subscription tags are added dynamically in Get-SubscriptionMap

# Legacy tags from previous script versions (v1.x) — cleaned automatically
$script:LEGACY_TAGS = @(
    "DUPLICATED", "EPHEMERAL_INACTIVE", "NO_SUBSCRIPTION",
    "IMPAIRED_COMMUNICATION", "REVIEW_NEEDED"
)

# API telemetry
$script:ApiCalls  = 0
$script:ApiErrors = 0

# Token cache
$script:Token           = $null
$script:TokenExpiry     = [datetime]::MinValue
$script:ArmToken        = $null
$script:ArmTokenExpiry  = [datetime]::MinValue
$script:ArmTokenFailed  = $false
$script:SubscriptionSource = "N/A"

# ============================================================================
# INITIALIZE CREDENTIALS — v3.0: Azure Automation Variables support
# ============================================================================
function Initialize-Credentials {
    if (-not $UseAzureAutomation) { return }

    Write-Log "Azure Automation mode — reading credentials from AA Variables..." -Level INFO

    try {
        if ([string]::IsNullOrWhiteSpace($script:tenantId_runtime)) {
            $script:tenantId_runtime = Get-AutomationVariable -Name $AaVarTenantId
        }
        if ([string]::IsNullOrWhiteSpace($script:appId_runtime)) {
            $script:appId_runtime = Get-AutomationVariable -Name $AaVarAppId
        }
        if ([string]::IsNullOrWhiteSpace($script:appSecret_runtime)) {
            $script:appSecret_runtime = Get-AutomationVariable -Name $AaVarAppSecret
        }
        Write-Log "AA Variables loaded (TenantId: $($script:tenantId_runtime.Substring(0,8))...)" -Level OK
    }
    catch {
        Write-Log "Failed to read AA Variables: $($_.Exception.Message)" -Level ERROR
        Write-Log "Ensure variables '$AaVarTenantId', '$AaVarAppId', '$AaVarAppSecret' exist in the Automation Account." -Level ERROR
        throw
    }
}

# ============================================================================
# LOG
# ============================================================================
function Write-Log {
    param ([string]$Msg, [string]$Level = "INFO")
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts [$Level] $Msg"
    Add-Content -Path $script:LogPath -Value $line -ErrorAction SilentlyContinue
    switch ($Level) {
        "INFO"  { Write-Host $line -ForegroundColor Cyan }
        "WARN"  { Write-Host $line -ForegroundColor Yellow }
        "ERROR" { Write-Host $line -ForegroundColor Red }
        "OK"    { Write-Host $line -ForegroundColor Green }
        "DEBUG" { Write-Host $line -ForegroundColor Gray }
        default { Write-Host $line }
    }
}

# ============================================================================
# AUTH — MDE Token (OAuth2 client_credentials)
# ============================================================================
function Get-MdeToken {
    # Resolve runtime credentials (AA Variables override parameters)
    $t = if ($UseAzureAutomation -and $script:tenantId_runtime) { $script:tenantId_runtime } else { $tenantId }
    $a = if ($UseAzureAutomation -and $script:appId_runtime)    { $script:appId_runtime    } else { $appId    }
    $s = if ($UseAzureAutomation -and $script:appSecret_runtime){ $script:appSecret_runtime} else { $appSecret}

    if ($script:Token -and (Get-Date) -lt $script:TokenExpiry) { return $script:Token }

    $body = @{
        client_id     = $a
        client_secret = $s
        grant_type    = "client_credentials"
        scope         = "https://api.securitycenter.microsoft.com/.default"
    }
    try {
        $r = Invoke-RestMethod -Method Post `
            -Uri "https://login.microsoftonline.com/$t/oauth2/v2.0/token" `
            -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        $script:Token       = $r.access_token
        $script:TokenExpiry = (Get-Date).AddSeconds($r.expires_in - 120)
        Write-Log "MDE Token obtained. Expires in $([math]::Round($r.expires_in/60))min" -Level OK
        return $script:Token
    }
    catch {
        Write-Log "MDE Auth FAILED: $($_.Exception.Message)" -Level ERROR
        throw
    }
}

# ============================================================================
# AUTH — ARM Token via Managed Identity (IMDS endpoint) — v3.0 NEW
# ============================================================================
function Get-ArmTokenManagedIdentity {
    try {
        $headers = @{ "Metadata" = "true" }
        $uri     = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F"
        $r       = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -TimeoutSec 10 -ErrorAction Stop
        if ($r.access_token) {
            $script:ArmToken       = $r.access_token
            $expirySecs            = if ($r.expires_in) { [int]$r.expires_in } else { 3600 }
            $script:ArmTokenExpiry = (Get-Date).AddSeconds($expirySecs - 120)
            Write-Log "ARM Token via Managed Identity obtained ($expirySecs s validity)" -Level OK
            return $script:ArmToken
        }
    }
    catch {
        Write-Log "IMDS/Managed Identity not available: $($_.Exception.Message)" -Level WARN
        $script:ArmTokenFailed = $true
    }
    return $null
}

# ============================================================================
# AUTH — ARM Token (client_credentials OR Managed Identity)
# ============================================================================
function Get-ArmToken {
    if ($script:ArmTokenFailed) { return $null }
    if ($script:ArmToken -and (Get-Date) -lt $script:ArmTokenExpiry) { return $script:ArmToken }

    # v3.0: Try Managed Identity first if requested
    if ($UseManagedIdentity) {
        $token = Get-ArmTokenManagedIdentity
        if ($token) { return $token }
        # MI failed — fall through to client_credentials
    }

    # Resolve runtime credentials
    $t = if ($UseAzureAutomation -and $script:tenantId_runtime) { $script:tenantId_runtime } else { $tenantId }
    $a = if ($UseAzureAutomation -and $script:appId_runtime)    { $script:appId_runtime    } else { $appId    }
    $s = if ($UseAzureAutomation -and $script:appSecret_runtime){ $script:appSecret_runtime} else { $appSecret}

    $body = @{
        client_id     = $a
        client_secret = $s
        grant_type    = "client_credentials"
        scope         = "https://management.azure.com/.default"
    }
    try {
        $r = Invoke-RestMethod -Method Post `
            -Uri "https://login.microsoftonline.com/$t/oauth2/v2.0/token" `
            -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        $script:ArmToken       = $r.access_token
        $script:ArmTokenExpiry = (Get-Date).AddSeconds($r.expires_in - 120)
        Write-Log "ARM Token (client_credentials) obtained. Expires in $([math]::Round($r.expires_in/60))min" -Level OK
        return $script:ArmToken
    }
    catch {
        $script:ArmTokenFailed = $true
        $code = 0
        if ($_.Exception.Response) { try { $code = [int]$_.Exception.Response.StatusCode } catch {} }
        Write-Log "ARM Token unavailable (HTTP $code) — App Reg may lack Reader role on subscriptions: $($_.Exception.Message)" -Level WARN
        return $null
    }
}

# ============================================================================
# MDE API — generic caller with pagination + retry (401 refresh, 429 backoff)
# ============================================================================
function Call-MdeApi {
    param (
        [string]$Uri,
        [string]$Method = "Get",
        [string]$Body   = $null
    )

    $all       = @()
    $url       = $Uri
    $retries   = 0
    $maxRetries= 3

    do {
        $headers = @{
            Authorization  = "Bearer $(Get-MdeToken)"
            "Content-Type" = "application/json"
        }
        try {
            $params = @{ Uri = $url; Headers = $headers; Method = $Method; ErrorAction = "Stop" }
            if ($Body) { $params.Body = $Body }

            Write-Log "API $Method $url" -Level DEBUG
            $resp = Invoke-RestMethod @params
            $script:ApiCalls++
            $retries = 0

            if ($resp.value) { $all += $resp.value } else { $all += $resp }
            $url = $resp.'@odata.nextLink'
        }
        catch {
            $script:ApiErrors++
            $code = 0
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                $code = [int]$_.Exception.Response.StatusCode
            }
            if ($code -eq 401 -and $retries -lt $maxRetries) {
                Write-Log "401 — refreshing token (attempt $($retries+1))..." -Level WARN
                $script:Token = $null; $retries++; continue
            }
            elseif ($code -eq 429 -and $retries -lt $maxRetries) {
                Write-Log "429 — rate limit, waiting 180s (attempt $($retries+1))..." -Level WARN
                Start-Sleep 180; $retries++; continue
            }
            else {
                Write-Log "API Error ($code): $($_.Exception.Message)" -Level ERROR
                throw
            }
        }
    } while ($url)

    return $all
}

# ============================================================================
# CONVERT subscription name → MDE tag (UPPERCASE, sanitized)
# ============================================================================
function ConvertTo-TagName {
    param ([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return "UNKNOWN" }
    $tag = $Name.ToUpper() -replace '[^A-Z0-9\-_\s]', '' -replace '\s+', '_' -replace '[-_]{2,}', '_'
    $tag = $tag.Trim('_', '-')
    if ($tag.Length -gt 200) { $tag = $tag.Substring(0, 200) }
    if ([string]::IsNullOrWhiteSpace($tag)) { return "UNKNOWN" }
    return $tag
}

# ============================================================================
# SUBSCRIPTION DISCOVERY — Level 2: Azure Resource Manager API
# ============================================================================
function Get-SubscriptionsFromArm {
    $token = Get-ArmToken
    if (-not $token) { return $null }

    try {
        $headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }
        $resp    = Invoke-RestMethod `
            -Uri "https://management.azure.com/subscriptions?api-version=2020-01-01" `
            -Headers $headers -Method Get -ErrorAction Stop

        $subs = @($resp.value | Where-Object { $_.state -eq 'Enabled' })
        if ($subs.Count -eq 0) {
            Write-Log "ARM: No enabled subscriptions found" -Level WARN
            return $null
        }
        Write-Log "ARM: $($subs.Count) enabled subscription(s) found" -Level OK
        return $subs | ForEach-Object {
            [PSCustomObject]@{ subscriptionId = $_.subscriptionId; subscriptionName = $_.displayName }
        }
    }
    catch {
        $code = 0
        if ($_.Exception.Response) { try { $code = [int]$_.Exception.Response.StatusCode } catch {} }
        $hint = if ($code -eq 403) { " — App Reg needs Reader role on subscriptions" } else { "" }
        Write-Log "ARM: HTTP $code$hint — $($_.Exception.Message)" -Level WARN
        $script:ArmTokenFailed = $true
        return $null
    }
}

# ============================================================================
# SUBSCRIPTION DISCOVERY — Level 3: Azure CLI
# ============================================================================
function Get-SubscriptionsFromAzCli {
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        Write-Log "AzCLI: 'az' not found in PATH" -Level WARN
        return $null
    }
    try {
        $json = & az account list `
            --query "[?state=='Enabled'].{subscriptionId:id,subscriptionName:name}" `
            --output json 2>$null

        if ($LASTEXITCODE -ne 0) {
            Write-Log "AzCLI: exit $LASTEXITCODE — run 'az login' first" -Level WARN
            return $null
        }
        $subs = $json | ConvertFrom-Json
        if (-not $subs -or $subs.Count -eq 0) {
            Write-Log "AzCLI: No subscriptions returned" -Level WARN
            return $null
        }
        Write-Log "AzCLI: $($subs.Count) subscription(s) found" -Level OK
        return $subs
    }
    catch {
        Write-Log "AzCLI: $($_.Exception.Message)" -Level WARN
        return $null
    }
}

# ============================================================================
# SUBSCRIPTION DISCOVERY — Level 4: MDE device vmMetadata (zero extra permissions)
# ============================================================================
function Build-SubscriptionMapFromDevices {
    param ([array]$Devices)

    $subIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($dev in $Devices) {
        $id = $null
        if ($dev.vmMetadata -and $dev.vmMetadata.resourceId -match '/subscriptions/([0-9a-f\-]{36})/') {
            $id = $Matches[1].ToLower()
        }
        elseif ($dev.vmMetadata -and -not [string]::IsNullOrWhiteSpace($dev.vmMetadata.subscriptionId)) {
            $id = $dev.vmMetadata.subscriptionId.ToLower()
        }
        if ($id) { $null = $subIds.Add($id) }
    }

    if ($subIds.Count -eq 0) {
        Write-Log "MDE-Metadata: No subscriptionIds found in device vmMetadata" -Level WARN
        return $null
    }
    Write-Log "MDE-Metadata: $($subIds.Count) subscriptionId(s) extracted from devices" -Level OK

    # Enrich names via ARM if still available
    $nameMap = @{}
    if (-not $script:ArmTokenFailed) {
        $armSubs = Get-SubscriptionsFromArm
        if ($armSubs) {
            foreach ($s in $armSubs) { $nameMap[$s.subscriptionId.ToLower()] = $s.subscriptionName }
            Write-Log "MDE-Metadata: Names enriched via ARM API" -Level OK
        }
    }

    $map     = @{}
    $csvRows = [System.Collections.Generic.List[PSCustomObject]]::new()
    $excludeLower = @($excludeSubscriptions | Where-Object { $_ } | ForEach-Object { $_.ToLower() })

    foreach ($id in $subIds) {
        if ($excludeLower -and $id -in $excludeLower) {
            Write-Log "  Sub: $id excluded (exclusion list)" -Level DEBUG
            continue
        }
        $name = if ($nameMap.ContainsKey($id)) { $nameMap[$id] } else { $id }
        $tag  = ConvertTo-TagName -Name $name
        $map[$id] = @{ Name = $name; Tag = $tag }
        if ($tag -notin $script:MANAGED_TAGS) { $script:MANAGED_TAGS.Add($tag) }
        Write-Log "  Sub: $id -> Tag '$tag' (MDE-Metadata)" -Level DEBUG
        $csvRows.Add([PSCustomObject]@{ subscriptionId = $id; subscriptionName = $name })
    }

    $script:SubscriptionSource = "MDE-Metadata"
    Write-Log "MDE-Metadata: $($map.Count) subscription(s) mapped" -Level OK

    if ($saveDiscoveredCsv -and $csvRows.Count -gt 0) {
        try {
            $csvRows | Export-Csv -Path $subscriptionMappingPath `
                -NoTypeInformation -Delimiter ';' -Encoding UTF8
            Write-Log "CSV saved (MDE-Metadata): $subscriptionMappingPath" -Level OK
        }
        catch { Write-Log "Warning: Could not save CSV: $($_.Exception.Message)" -Level WARN }
    }

    return $map
}

# ============================================================================
# LOAD SUBSCRIPTION MAP — 4-level cascade orchestrator
# Returns: hashtable { subscriptionId => @{Name; Tag} }
# Returns $null when Level 4 is needed (caller must run Build-SubscriptionMapFromDevices)
# ============================================================================
function Get-SubscriptionMap {
    $rawSubs     = $null
    $excludeLower= @($excludeSubscriptions | Where-Object { $_ } | ForEach-Object { $_.ToLower() })

    # Level 1: CSV
    if (-not [string]::IsNullOrWhiteSpace($subscriptionMappingPath) -and (Test-Path $subscriptionMappingPath)) {
        $content = Get-Content $subscriptionMappingPath -Raw
        $parsed  = $content | ConvertFrom-Csv -Delimiter ';'
        # Only use CSV if it has actual data rows (not just header)
        if ($parsed -and @($parsed).Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($parsed[0].subscriptionId)) {
            Write-Log "Level 1 — CSV found with data: $subscriptionMappingPath" -Level OK
            $rawSubs = $parsed
            $script:SubscriptionSource = "CSV"
        }
        else {
            Write-Log "Level 1 — CSV exists but has no data rows. Proceeding to auto-discovery." -Level WARN
        }
    }

    if (-not $rawSubs -and $autoDiscoverSubscriptions) {
        Write-Log "Starting auto-discovery cascade..." -Level WARN

        Write-Log "Level 2 — Azure Resource Manager API..." -Level INFO
        $rawSubs = Get-SubscriptionsFromArm
        if ($rawSubs) { $script:SubscriptionSource = "ARM API" }

        if (-not $rawSubs) {
            Write-Log "Level 3 — Azure CLI..." -Level INFO
            $rawSubs = Get-SubscriptionsFromAzCli
            if ($rawSubs) { $script:SubscriptionSource = "Azure CLI" }
        }

        if (-not $rawSubs) {
            Write-Log "Level 4 — MDE device metadata will be processed after device retrieval." -Level WARN
            return $null  # Signal for MAIN to call Build-SubscriptionMapFromDevices
        }

        # Persist discovered subscriptions for future runs
        if ($saveDiscoveredCsv) {
            try {
                $rawSubs |
                    Select-Object @{N='subscriptionId';   E={$_.subscriptionId}},
                                  @{N='subscriptionName'; E={$_.subscriptionName}} |
                    Export-Csv -Path $subscriptionMappingPath `
                        -NoTypeInformation -Delimiter ';' -Encoding UTF8
                Write-Log "CSV saved automatically: $subscriptionMappingPath (source: $($script:SubscriptionSource))" -Level OK
            }
            catch { Write-Log "Warning: Could not save CSV: $($_.Exception.Message)" -Level WARN }
        }
    }
    elseif (-not $rawSubs -and -not $autoDiscoverSubscriptions) {
        Write-Log "CSV not found: $subscriptionMappingPath" -Level ERROR
        throw "Mapping not found: '$subscriptionMappingPath'. Create the CSV or set: -autoDiscoverSubscriptions `$true"
    }

    # Build hashtable
    $map = @{}
    foreach ($row in $rawSubs) {
        $id   = if ($row.PSObject.Properties['subscriptionId'])   { ($row.subscriptionId   + '').Trim().ToLower() } else { $null }
        $name = if ($row.PSObject.Properties['subscriptionName']) { ($row.subscriptionName + '').Trim()           } else { $null }
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        if ($excludeLower -and $id -in $excludeLower) { Write-Log "  Sub: $id excluded" -Level DEBUG; continue }
        if ([string]::IsNullOrWhiteSpace($name)) { $name = $id }

        $tag = ConvertTo-TagName -Name $name
        $map[$id] = @{ Name = $name; Tag = $tag }
        if ($tag -notin $script:MANAGED_TAGS) { $script:MANAGED_TAGS.Add($tag) }
        Write-Log "  Sub: $id -> Tag '$tag' ($($script:SubscriptionSource))" -Level DEBUG
    }

    Write-Log "Subscriptions loaded: $($map.Count) (source: $($script:SubscriptionSource))" -Level OK
    return $map
}

# ============================================================================
# FILTER DEVICES — Windows Server + Linux only (Azure VM or Azure Arc)
# ============================================================================
function Get-Servers {
    param ([array]$AllDevices)

    $linuxDistros = @(
        "Ubuntu", "RedHatEnterpriseLinux", "SuseLinuxEnterpriseServer",
        "OracleLinux", "CentOS", "Debian", "Fedora", "Linux",
        "AmazonLinux", "Mariner", "AlmaLinux", "RockyLinux"
    )

    $servers = $AllDevices | Where-Object {
        $isServer = $false
        if ($_.osPlatform -like "*Server*") { $isServer = $true }
        if ($_.osPlatform -in $linuxDistros -or
            $_.osPlatform -match '(?i)Linux|Ubuntu|RedHat|SUSE|CentOS|Debian|Oracle|Fedora|Mariner|Alma|Rocky') {
            $isServer = $true
        }
        if ([string]::IsNullOrWhiteSpace($_.computerDnsName) -or $_.computerDnsName.Length -lt 3) {
            $isServer = $false
        }
        $isServer
    }

    Write-Log "Servers filtered: $($servers.Count) of $($AllDevices.Count) total devices" -Level OK
    return $servers
}

# ============================================================================
# DATE PARSING — InvariantCulture (locale-safe)
# ============================================================================
function Parse-MdeDate {
    param ([string]$DateStr)
    if ([string]::IsNullOrWhiteSpace($DateStr)) { return [datetime]::MinValue }
    try { return [datetime]::Parse($DateStr, [System.Globalization.CultureInfo]::InvariantCulture) }
    catch { return [datetime]::MinValue }
}

# ============================================================================
# CLASSIFICATION ENGINE — 5-priority lifecycle decision tree
# Uses configurable thresholds from $script:Thresholds
# ============================================================================
function Get-ServerClassification {
    param (
        [array]    $Servers,
        [hashtable]$SubMap
    )

    $now = Get-Date

    # ── Step 1: Detect hostname duplicates ──────────────────────────────────
    $groups      = $Servers | Group-Object { $_.computerDnsName.ToLower() }
    $duplicateIds= @{}

    foreach ($g in $groups) {
        if ($g.Count -le 1) { continue }
        # VMSS: hostname ends in _0, _1, _000000, etc — intentional, skip
        if ($g.Name -match '_\d+$|\d{6}$|(?i)vmss|scaleset') {
            Write-Log "VMSS pattern: '$($g.Name)' ($($g.Count) instances) — not flagged as duplicate" -Level WARN
            continue
        }
        $sorted = $g.Group | Sort-Object { Parse-MdeDate $_.lastSeen } -Descending
        for ($i = 1; $i -lt $sorted.Count; $i++) { $duplicateIds[$sorted[$i].id] = $true }
        Write-Log "Duplicate: '$($g.Name)' — keeping ID $($sorted[0].id), flagging $($g.Count - 1) as DUPLICADA_EXCLUIR" -Level WARN
    }
    Write-Log "Total duplicates detected: $($duplicateIds.Count)" -Level INFO

    # ── Step 2: Classify each server ────────────────────────────────────────
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($srv in $Servers) {
        $lastSeen      = Parse-MdeDate $srv.lastSeen
        $firstSeen     = Parse-MdeDate $srv.firstSeen
        $daysInactive  = if ($lastSeen  -gt [datetime]::MinValue) { ($now - $lastSeen ).TotalDays  } else { 999 }
        $lifespanHours = if ($firstSeen -gt [datetime]::MinValue -and $lastSeen -gt [datetime]::MinValue) {
            ($lastSeen - $firstSeen).TotalHours
        } else { 999 }

        $tag    = $null
        $subId  = $null
        $action = "SKIP"
        $reason = ""

        # ── P1: Duplicate ──────────────────────────────────────────────────
        if ($duplicateIds.ContainsKey($srv.id)) {
            $tag    = "DUPLICADA_EXCLUIR"
            $action = "TAG"
            $reason = "Duplicate hostname — older record (lastSeen: $($srv.lastSeen))"
        }
        # ── P2: Ephemeral ─────────────────────────────────────────────────
        # v3.0: threshold configurable via $script:Thresholds.HorasEfemero
        elseif ($lifespanHours -le $script:Thresholds.HorasEfemero -and
                $srv.healthStatus -in @("Inactive", "NoSensorData") -and
                $daysInactive -gt 1) {
            # Exception: if VM still exists in Azure with mapped subscription, use subscription tag
            $ephSubId = $null
            if ($srv.vmMetadata -and $srv.vmMetadata.resourceId -match '/subscriptions/([0-9a-f\-]{36})/') {
                $ephSubId = $Matches[1].ToLower()
            }
            elseif ($srv.vmMetadata -and -not [string]::IsNullOrWhiteSpace($srv.vmMetadata.subscriptionId)) {
                $ephSubId = $srv.vmMetadata.subscriptionId.ToLower()
            }

            if ($ephSubId -and $SubMap.ContainsKey($ephSubId)) {
                $tag    = $SubMap[$ephSubId].Tag
                $subId  = $ephSubId
                $action = "TAG"
                $reason = "Ephemeral reclassified — VM exists in Azure (Sub: $($SubMap[$ephSubId].Name)), lived $([math]::Round($lifespanHours,1))h"
            }
            else {
                $tag    = "EFEMERO"
                $action = "TAG"
                $reason = "Ephemeral — lived $([math]::Round($lifespanHours,1))h, no active Azure link, first=$($srv.firstSeen), last=$($srv.lastSeen)"
            }
        }
        # ── P3: Inactive > diasInativo40d ─────────────────────────────────
        elseif ($daysInactive -gt $script:Thresholds.DiasInativo40d) {
            $tag    = "INATIVO_40D"
            $action = "TAG"
            $reason = "No communication for $([math]::Round($daysInactive,0)) days (threshold: $($script:Thresholds.DiasInativo40d)d)"
        }
        # ── P4: Inactive > diasInativo7d ──────────────────────────────────
        elseif ($daysInactive -gt $script:Thresholds.DiasInativo7d) {
            $tag    = "INATIVO_7D"
            $action = "TAG"
            $reason = "No communication for $([math]::Round($daysInactive,0)) days (threshold: $($script:Thresholds.DiasInativo7d)d)"
        }
        # ── P5: Active with known subscription ────────────────────────────
        else {
            $subId = $null
            if ($srv.vmMetadata -and $srv.vmMetadata.resourceId -match '/subscriptions/([0-9a-f\-]{36})/') {
                $subId = $Matches[1].ToLower()
            }
            elseif ($srv.vmMetadata -and -not [string]::IsNullOrWhiteSpace($srv.vmMetadata.subscriptionId)) {
                $subId = $srv.vmMetadata.subscriptionId.ToLower()
            }

            if ($subId -and $SubMap.ContainsKey($subId)) {
                $tag    = $SubMap[$subId].Tag
                $action = "TAG"
                $reason = "Subscription: $($SubMap[$subId].Name)"
            }
            elseif ($subId) {
                $action = "SKIP"
                $reason = "Subscription '$subId' not mapped — excluded or undiscovered"
            }
            else {
                $action = "SKIP"
                $reason = "Active, no Azure subscription (on-prem without Arc?)"
            }
        }

        # ── Check current tags vs target ───────────────────────────────────
        $currentTags        = @()
        if ($srv.machineTags) { $currentTags = @($srv.machineTags) }

        $allKnownTags        = @($script:MANAGED_TAGS) + $script:LEGACY_TAGS
        $currentManagedTags  = @($currentTags | Where-Object { $_ -in $allKnownTags })
        $tagsToRemove        = @($currentManagedTags | Where-Object { $_ -ne $tag })
        $needsAdd            = ($tag -and ($tag -notin $currentTags))
        $needsRemove         = ($tagsToRemove.Count -gt 0)

        if (-not $needsAdd -and -not $needsRemove -and $tag) {
            $action = "OK"
            $reason = "Tag '$tag' already correct"
        }
        elseif ($action -eq "SKIP" -and $needsRemove) {
            $action = "CLEAN"
            $reason = "$reason — cleaning legacy tags: $($tagsToRemove -join ', ')"
        }

        $results.Add([PSCustomObject]@{
            MachineId       = $srv.id
            ComputerDnsName = $srv.computerDnsName
            OsPlatform      = $srv.osPlatform
            HealthStatus    = $srv.healthStatus
            FirstSeen       = $srv.firstSeen
            LastSeen        = $srv.lastSeen
            DaysInactive    = [math]::Round($daysInactive, 0)
            LifespanHours   = [math]::Round($lifespanHours, 1)
            SubscriptionId  = if ($subId) { $subId } else { "" }
            CurrentTags     = ($currentTags -join ", ")
            TargetTag       = if ($tag) { $tag } else { "" }
            TagsToRemove    = ($tagsToRemove -join ", ")
            NeedsAdd        = $needsAdd
            NeedsRemove     = $needsRemove
            Action          = $action
            Reason          = $reason
        })
    }

    $tagCount   = @($results | Where-Object Action -eq "TAG").Count
    $okCount    = @($results | Where-Object Action -eq "OK").Count
    $cleanCount = @($results | Where-Object Action -eq "CLEAN").Count
    $skipCount  = @($results | Where-Object Action -eq "SKIP").Count
    Write-Log "Classification: TAG=$tagCount | OK=$okCount | CLEAN=$cleanCount | SKIP=$skipCount" -Level OK

    return $results
}

# ============================================================================
# APPLY TAGS — Phase 1: Remove old → Phase 2: Add new (bulk API, 25/call)
# Falls back to individual endpoint if bulk API returns 403
# ============================================================================
function Set-Tags {
    param ([System.Collections.Generic.List[PSCustomObject]]$Results)

    if ($reportOnly) {
        Write-Log "=== REPORT-ONLY MODE — no tags will be changed ===" -Level WARN
        return @{ Added = 0; Removed = 0; Errors = 0 }
    }

    Write-Log "=== APPLYING TAGS (LIVE EXECUTION) ===" -Level WARN

    $removals  = @{}  # tag -> @(machineIds)
    $additions = @{}  # tag -> @(machineIds)

    foreach ($r in $Results) {
        if ($r.Action -notin @("TAG", "CLEAN")) { continue }
        if ($r.NeedsRemove -and $r.TagsToRemove) {
            foreach ($old in ($r.TagsToRemove -split ',\s*' | Where-Object { $_ })) {
                if (-not $removals.ContainsKey($old)) { $removals[$old] = @() }
                $removals[$old] += $r.MachineId
            }
        }
        if ($r.Action -eq "TAG" -and $r.NeedsAdd -and $r.TargetTag) {
            if (-not $additions.ContainsKey($r.TargetTag)) { $additions[$r.TargetTag] = @() }
            $additions[$r.TargetTag] += $r.MachineId
        }
    }

    $totalRemoved = 0; $totalAdded = 0; $errors = 0
    $bulkUri      = "https://api.securitycenter.microsoft.com/api/machines/AddOrRemoveTagForMultipleMachines"
    $useFallback  = $false

    # ── Phase 1: Remove ───────────────────────────────────────────────────────
    if ($removals.Count -gt 0) {
        Write-Log "── Phase 1: Tag removal ──" -Level INFO
        foreach ($tag in $removals.Keys) {
            $ids = @($removals[$tag])
            Write-Log "Removing '$tag' from $($ids.Count) devices..." -Level INFO
            if (-not $useFallback) {
                for ($i = 0; $i -lt $ids.Count; $i += 25) {
                    $chunk = @($ids[$i..[Math]::Min($i + 24, $ids.Count - 1)])
                    $body  = @{ Value = $tag; Action = "Remove"; MachineIds = $chunk } | ConvertTo-Json -Depth 3
                    try {
                        $null = Call-MdeApi -Uri $bulkUri -Method Post -Body $body
                        $totalRemoved += $chunk.Count
                        Write-Log "  + Removed '$tag' from $($chunk.Count) (batch $([Math]::Floor($i/25)+1))" -Level OK
                    }
                    catch {
                        if ($_.Exception.Message -match '403|Forbidden') {
                            Write-Log "  Bulk API unavailable (403). Switching to individual endpoint..." -Level WARN
                            $useFallback = $true
                            foreach ($mid in $chunk) {
                                try { $null = Call-MdeApi -Uri "https://api.securitycenter.microsoft.com/api/machines/$mid/tags" -Method Post -Body (@{Value=$tag;Action="Remove"}|ConvertTo-Json); $totalRemoved++ }
                                catch { $errors++ }
                                Start-Sleep 1
                            }
                            for ($j = $i + 25; $j -lt $ids.Count; $j++) {
                                try { $null = Call-MdeApi -Uri "https://api.securitycenter.microsoft.com/api/machines/$($ids[$j])/tags" -Method Post -Body (@{Value=$tag;Action="Remove"}|ConvertTo-Json); $totalRemoved++ }
                                catch { $errors++ }
                                Start-Sleep 1
                            }
                            break
                        }
                        $errors++; Write-Log "  ERROR removing '$tag': $($_.Exception.Message)" -Level ERROR
                    }
                    Start-Sleep 5
                }
            }
            else {
                foreach ($mid in $ids) {
                    try { $null = Call-MdeApi -Uri "https://api.securitycenter.microsoft.com/api/machines/$mid/tags" -Method Post -Body (@{Value=$tag;Action="Remove"}|ConvertTo-Json); $totalRemoved++ }
                    catch { $errors++ }
                    Start-Sleep 1
                }
            }
        }
    }

    if ($totalRemoved -gt 0) { Write-Log "Waiting 15s between remove and add phases..." -Level INFO; Start-Sleep 15 }

    # ── Phase 2: Add ──────────────────────────────────────────────────────────
    if ($additions.Count -gt 0) {
        Write-Log "── Phase 2: Tag addition ──" -Level INFO
        foreach ($tag in $additions.Keys) {
            $ids = @($additions[$tag])
            Write-Log "Adding '$tag' to $($ids.Count) devices..." -Level INFO
            if (-not $useFallback) {
                for ($i = 0; $i -lt $ids.Count; $i += 25) {
                    $chunk = @($ids[$i..[Math]::Min($i + 24, $ids.Count - 1)])
                    $body  = @{ Value = $tag; Action = "Add"; MachineIds = $chunk } | ConvertTo-Json -Depth 3
                    try {
                        $null = Call-MdeApi -Uri $bulkUri -Method Post -Body $body
                        $totalAdded += $chunk.Count
                        Write-Log "  + Added '$tag' to $($chunk.Count) (batch $([Math]::Floor($i/25)+1))" -Level OK
                    }
                    catch {
                        if ($_.Exception.Message -match '403|Forbidden') {
                            $useFallback = $true
                            foreach ($mid in $chunk) {
                                try { $null = Call-MdeApi -Uri "https://api.securitycenter.microsoft.com/api/machines/$mid/tags" -Method Post -Body (@{Value=$tag;Action="Add"}|ConvertTo-Json); $totalAdded++ }
                                catch { $errors++ }
                                Start-Sleep 1
                            }
                            for ($j = $i + 25; $j -lt $ids.Count; $j++) {
                                try { $null = Call-MdeApi -Uri "https://api.securitycenter.microsoft.com/api/machines/$($ids[$j])/tags" -Method Post -Body (@{Value=$tag;Action="Add"}|ConvertTo-Json); $totalAdded++ }
                                catch { $errors++ }
                                Start-Sleep 1
                            }
                            break
                        }
                        $errors++; Write-Log "  ERROR adding '$tag': $($_.Exception.Message)" -Level ERROR
                    }
                    Start-Sleep 5
                }
            }
            else {
                foreach ($mid in $ids) {
                    try { $null = Call-MdeApi -Uri "https://api.securitycenter.microsoft.com/api/machines/$mid/tags" -Method Post -Body (@{Value=$tag;Action="Add"}|ConvertTo-Json); $totalAdded++ }
                    catch { $errors++ }
                    Start-Sleep 1
                }
            }
        }
    }

    Write-Log "Tags applied: +$totalAdded added, -$totalRemoved removed, $errors errors" -Level $(if ($errors -gt 0) { "WARN" } else { "OK" })
    return @{ Added = $totalAdded; Removed = $totalRemoved; Errors = $errors }
}

# ============================================================================
# EXPORT — Main report (CSV + visual console summary)
# ============================================================================
function Export-TagReport {
    param (
        [System.Collections.Generic.List[PSCustomObject]]$Results,
        [hashtable]$Stats
    )

    $Results | Select-Object MachineId, ComputerDnsName, OsPlatform, HealthStatus, `
        FirstSeen, LastSeen, DaysInactive, LifespanHours, SubscriptionId, `
        CurrentTags, TargetTag, TagsToRemove, Action, Reason |
        Export-Csv -Path $script:ReportPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'

    Write-Log "Report CSV: $($script:ReportPath)" -Level OK

    $total      = $Results.Count
    $tagCount   = ($Results | Where-Object Action -eq "TAG").Count
    $okCount    = ($Results | Where-Object Action -eq "OK").Count
    $cleanCount = ($Results | Where-Object Action -eq "CLEAN").Count
    $skipCount  = ($Results | Where-Object Action -eq "SKIP").Count
    $byTag      = $Results | Where-Object { $_.TargetTag } | Group-Object TargetTag | Sort-Object Count -Descending

    # Offboard summary
    $offboard40d  = ($Results | Where-Object TargetTag -eq "INATIVO_40D").Count
    $duplicates   = ($Results | Where-Object TargetTag -eq "DUPLICADA_EXCLUIR").Count
    $offboardTotal= $offboard40d + $duplicates

    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  MDE Device Governance — Lifecycle Engine v$($script:Version)        ║" -ForegroundColor Cyan
    $modeText  = if ($reportOnly) { "REPORT-ONLY (simulation)" } else { "LIVE (tags applied)" }
    $modeColor = if ($reportOnly) { "Green" } else { "Yellow" }
    Write-Host "║  Mode: $($modeText.PadRight(53))║" -ForegroundColor $modeColor
    Write-Host "║  Subs: $($script:SubscriptionSource.PadRight(53))║" -ForegroundColor Gray
    Write-Host "║  Thresholds: INATIVO_7D=$($script:Thresholds.DiasInativo7d)d | INATIVO_40D=$($script:Thresholds.DiasInativo40d)d | EFEMERO=$($script:Thresholds.HorasEfemero)h $((' ').PadRight(8))║" -ForegroundColor Gray
    Write-Host "║  Date: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')$((' ').PadRight(38))║" -ForegroundColor White
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║  SERVERS ANALYZED                                            ║" -ForegroundColor Cyan
    Write-Host "║    Total:          $("{0,6}" -f $total)                               ║" -ForegroundColor White
    Write-Host "║    To tag (TAG):   $("{0,6}" -f $tagCount)                               ║" -ForegroundColor White
    Write-Host "║    Correct (OK):   $("{0,6}" -f $okCount)                               ║" -ForegroundColor Green
    Write-Host "║    Cleanup (CLEAN):$("{0,6}" -f $cleanCount)                               ║" -ForegroundColor Yellow
    Write-Host "║    Skipped (SKIP): $("{0,6}" -f $skipCount)                               ║" -ForegroundColor Gray
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║  TAG DISTRIBUTION                                            ║" -ForegroundColor Cyan
    foreach ($g in $byTag) {
        $name = $g.Name; if ($name.Length -gt 40) { $name = $name.Substring(0,37) + "..." }
        Write-Host "║    $("{0,-42}" -f $name)$("{0,4}" -f $g.Count) srv  ║" -ForegroundColor White
    }
    if ($offboardTotal -gt 0) {
        Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Yellow
        Write-Host "║  !! OFFBOARD CANDIDATES: $("{0,3}" -f $offboardTotal)                                  ║" -ForegroundColor Yellow
        Write-Host "║    INATIVO_40D:    $("{0,4}" -f $offboard40d) devices (investigate before offboard)  ║" -ForegroundColor Yellow
        Write-Host "║    DUPLICADA:      $("{0,4}" -f $duplicates) devices (oldest record — safe to remove) ║" -ForegroundColor Yellow
    }
    if (-not $reportOnly -and $Stats) {
        Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
        Write-Host "║  ACTIONS EXECUTED                                            ║" -ForegroundColor Cyan
        Write-Host "║    Tags added:   $("{0,6}" -f $Stats.Added)                               ║" -ForegroundColor Green
        Write-Host "║    Tags removed: $("{0,6}" -f $Stats.Removed)                               ║" -ForegroundColor Yellow
        Write-Host "║    Errors:       $("{0,6}" -f $Stats.Errors)                               ║" -ForegroundColor $(if ($Stats.Errors -gt 0) {"Red"} else {"Green"})
    }
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║  API: $($script:ApiCalls) calls, $($script:ApiErrors) errors$((' ').PadRight(43))║" -ForegroundColor White
    Write-Host "║  Log: $($script:LogPath)" -ForegroundColor White
    Write-Host "║  CSV: $($script:ReportPath)" -ForegroundColor White
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

# ============================================================================
# EXPORT — Offboard candidates (INATIVO_40D + DUPLICADA_EXCLUIR)  — v3.0 NEW
# ============================================================================
function Export-OffboardCandidates {
    param ([System.Collections.Generic.List[PSCustomObject]]$Results)

    if ([string]::IsNullOrWhiteSpace($OffboardCandidateReportPath)) { return }

    $candidates = $Results | Where-Object { $_.TargetTag -in @("INATIVO_40D", "DUPLICADA_EXCLUIR") }
    if ($candidates.Count -eq 0) {
        Write-Log "No offboard candidates in this run." -Level INFO
        return
    }

    # Ensure directory exists
    $dir = Split-Path $OffboardCandidateReportPath -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $candidates | Select-Object MachineId, ComputerDnsName, OsPlatform, HealthStatus,
        FirstSeen, LastSeen, DaysInactive, TargetTag, Reason |
        Export-Csv -Path $OffboardCandidateReportPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'

    Write-Log "Offboard candidates: $($candidates.Count) exported to $OffboardCandidateReportPath" -Level WARN
    Write-Log "  INATIVO_40D: $(@($candidates | Where-Object TargetTag -eq 'INATIVO_40D').Count) | DUPLICADA_EXCLUIR: $(@($candidates | Where-Object TargetTag -eq 'DUPLICADA_EXCLUIR').Count)" -Level WARN
}

# ============================================================================
# NOTIFY — Webhook HTTP POST (Teams, Slack, Logic Apps)  — v3.0 NEW
# ============================================================================
function Send-WebhookNotification {
    param (
        [System.Collections.Generic.List[PSCustomObject]]$Results,
        [hashtable]$Stats
    )

    if ([string]::IsNullOrWhiteSpace($NotifyWebhookUrl)) { return }

    $summary = @{
        source           = "MDE-DeviceGovernance"
        version          = $script:Version
        timestamp        = (Get-Date -Format "o")
        mode             = if ($reportOnly) { "report-only" } else { "live" }
        subscriptionSource = $script:SubscriptionSource
        thresholds       = $script:Thresholds
        totals           = @{
            analyzed = $Results.Count
            toTag    = ($Results | Where-Object Action -eq "TAG").Count
            correct  = ($Results | Where-Object Action -eq "OK").Count
            skipped  = ($Results | Where-Object Action -eq "SKIP").Count
        }
        tagDistribution  = @(
            $Results | Where-Object { $_.TargetTag } |
            Group-Object TargetTag |
            ForEach-Object { @{ tag = $_.Name; count = $_.Count } }
        )
        offboardCandidates = @{
            inativo40d         = ($Results | Where-Object TargetTag -eq "INATIVO_40D").Count
            duplicada_excluir  = ($Results | Where-Object TargetTag -eq "DUPLICADA_EXCLUIR").Count
        }
        apiStats         = @{ calls = $script:ApiCalls; errors = $script:ApiErrors }
        applied          = $Stats
    }

    try {
        $body = $summary | ConvertTo-Json -Depth 6 -Compress
        Invoke-RestMethod -Uri $NotifyWebhookUrl -Method Post -Body $body -ContentType "application/json" -ErrorAction Stop | Out-Null
        Write-Log "Webhook notification sent: $NotifyWebhookUrl" -Level OK
    }
    catch {
        Write-Log "Webhook failed (non-critical): $($_.Exception.Message)" -Level WARN
    }
}

# ============================================================================
# MAIN
# ============================================================================
try {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║  MDE Device Governance — Lifecycle Engine v$($script:Version) ║" -ForegroundColor Cyan
    Write-Host "  ║  github.com/rfranca777/MDE-DeviceGovernance          ║" -ForegroundColor Gray
    Write-Host "  ╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    if ($reportOnly) {
        Write-Host "  [REPORT-ONLY] No changes will be made (safe mode)." -ForegroundColor Green
    } else {
        Write-Host "  [LIVE MODE] Tags WILL be applied to MDE!" -ForegroundColor Yellow
    }
    Write-Host "  Thresholds: INATIVO_7D=$($script:Thresholds.DiasInativo7d)d | INATIVO_40D=$($script:Thresholds.DiasInativo40d)d | EFEMERO=$($script:Thresholds.HorasEfemero)h" -ForegroundColor Gray
    Write-Host ""

    # Step 1: Initialize credentials (Azure Automation Variables if requested)
    Write-Log "=== STEP 1/7: Credential Initialization ===" -Level INFO
    $script:tenantId_runtime  = $tenantId
    $script:appId_runtime     = $appId
    $script:appSecret_runtime = $appSecret
    Initialize-Credentials

    # Validate minimum credentials
    $rt = if ($UseAzureAutomation) { $script:tenantId_runtime  } else { $tenantId  }
    $ra = if ($UseAzureAutomation) { $script:appId_runtime     } else { $appId     }
    $rs = if ($UseAzureAutomation) { $script:appSecret_runtime } else { $appSecret }
    if ([string]::IsNullOrWhiteSpace($rt) -or [string]::IsNullOrWhiteSpace($ra) -or [string]::IsNullOrWhiteSpace($rs)) {
        throw "Missing credentials. Provide -tenantId, -appId, -appSecret or use -UseAzureAutomation `$true"
    }

    # Step 2: Authenticate
    Write-Log "=== STEP 2/7: Authentication ===" -Level INFO
    $null = Get-MdeToken

    # Step 3: Load subscription map (Levels 1-3)
    Write-Log "=== STEP 3/7: Loading subscription mapping ===" -Level INFO
    $subMap = Get-SubscriptionMap

    # Step 4: Get all devices from MDE
    Write-Log "=== STEP 4/7: Retrieving all devices from MDE ===" -Level INFO
    $allDevices = Call-MdeApi -Uri "https://api.securitycenter.microsoft.com/api/machines"
    Write-Log "Total devices in MDE: $($allDevices.Count)" -Level INFO

    # Step 4b: Level 4 discovery (device metadata) — only when Levels 1-3 failed
    if ($null -eq $subMap -and $autoDiscoverSubscriptions) {
        Write-Log "=== STEP 4b/7: Level 4 subscription discovery (MDE metadata) ===" -Level INFO
        $subMap = Build-SubscriptionMapFromDevices -Devices $allDevices
    }
    if ($null -eq $subMap) {
        Write-Log "WARNING: No subscription mapping found. Active servers won't receive subscription tags." -Level WARN
        $subMap = @{}
    }

    # Step 5: Filter servers (Windows Server + Linux only)
    Write-Log "=== STEP 5/7: Filtering servers ===" -Level INFO
    $servers = Get-Servers -AllDevices $allDevices
    if ($servers.Count -eq 0) {
        throw "No servers found in MDE. Check environment and App Registration permissions."
    }

    # Step 6: Classify
    Write-Log "=== STEP 6/7: Classifying devices (5-priority lifecycle engine) ===" -Level INFO
    $results = Get-ServerClassification -Servers $servers -SubMap $subMap

    # Step 7: Apply tags (or report only) + export
    Write-Log "=== STEP 7/7: $(if($reportOnly){'Generating report'}else{'Applying tags + generating report'}) ===" -Level INFO
    $stats = Set-Tags -Results $results

    # Export reports
    Export-TagReport -Results $results -Stats $stats
    Export-OffboardCandidates -Results $results
    Send-WebhookNotification -Results $results -Stats $stats

    Write-Log "Lifecycle engine completed successfully." -Level OK
}
catch {
    Write-Log "FATAL ERROR: $($_.Exception.Message)" -Level ERROR
    Write-Log "Stack: $($_.ScriptStackTrace)" -Level ERROR
    throw
}
finally {
    Write-Host "### Completed — $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ###" -ForegroundColor Green
}

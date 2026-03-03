<#
.SYNOPSIS
    Runbook-Lifecycle.ps1 v3.0.0
    Azure Automation Runbook — MDE Device Lifecycle Classification

.DESCRIPTION
    Azure Automation native wrapper for Invoke-MDE-DeviceLifecycle.ps1.
    Designed to run fully unattended in Azure Automation with:
    - System-Assigned Managed Identity for ARM operations (zero secrets for sub discovery)
    - Azure Automation Variables for MDE API credentials (encrypted at rest)
    - Full lifecycle classification: EFEMERO, INATIVO_7D, INATIVO_40D, DUPLICADA_EXCLUIR, {SUBSCRIPTION}

    REQUIRED AUTOMATION VARIABLES (created by Deploy-MDE-DeviceGovernance.ps1 Stage 15):
    - MDEGovernance-TenantId   (plain text)
    - MDEGovernance-AppId      (plain text)
    - MDEGovernance-AppSecret  (encrypted)

    REQUIRED PERMISSIONS:
    - Managed Identity: Reader on all in-scope subscriptions
    - App Registration: Machine.ReadWrite.All on MDE API

    EXECUTION MODES:
    - ReportOnly = $true  (safe — default)  → classifies but does NOT apply tags
    - ReportOnly = $false (live)             → applies tags via MDE API bulk endpoint
#>

param(
    [bool]$ReportOnly          = $true,
    [int]$DiasInativo7d        = 7,
    [int]$DiasInativo40d       = 40,
    [int]$HorasEfemero         = 48,
    [string]$WebhookUrl        = "",
    [bool]$AutoDiscover        = $true
)

$ErrorActionPreference = "Stop"
$runbookVersion = "3.0.0"

Write-Output "=============================================="
Write-Output "  MDE-DeviceGovernance Lifecycle Runbook"
Write-Output "  Version: $runbookVersion"
Write-Output "  Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC"
Write-Output "  Mode: $(if($ReportOnly){'REPORT-ONLY'}else{'LIVE - TAGS WILL BE APPLIED'})"
Write-Output "=============================================="

# ── Connect with Managed Identity ─────────────────────────────────────────────
Write-Output "[AUTH] Connecting with System-Assigned Managed Identity..."
try {
    Disable-AzContextAutosave -Scope Process | Out-Null
    $conn = Connect-AzAccount -Identity -ErrorAction Stop
    Write-Output "[AUTH] Connected: $($conn.Context.Account.Id)"
} catch {
    Write-Error "[AUTH] Managed Identity connection failed: $($_.Exception.Message)"
}

# ── Load credentials from AA Variables ────────────────────────────────────────
Write-Output "[CREDS] Loading credentials from Automation Variables..."
try {
    $tenantId  = Get-AutomationVariable -Name "MDEGovernance-TenantId"
    $appId     = Get-AutomationVariable -Name "MDEGovernance-AppId"
    $appSecret = Get-AutomationVariable -Name "MDEGovernance-AppSecret"
    Write-Output "[CREDS] Loaded: TenantId=$tenantId AppId=$appId AppSecret=***"
} catch {
    Write-Error "[CREDS] Failed to load Automation Variables. Ensure MDEGovernance-TenantId, MDEGovernance-AppId, MDEGovernance-AppSecret exist: $($_.Exception.Message)"
}

# ── Resolve lifecycle script path ─────────────────────────────────────────────
# In Azure Automation, files are expected in the Automation Account's module/runbook context.
# The lifecycle script should be uploaded as a module file or sourced inline.
# For simplicity, we dot-source the lifecycle script by its known relative path.
$lifecycleScript = "$PSScriptRoot\..\01-Core-Engine\Invoke-MDE-DeviceLifecycle.ps1"
if (-not (Test-Path $lifecycleScript)) {
    # Azure Automation stores runbooks in a flat directory — try current directory
    $lifecycleScript = "$PSScriptRoot\Invoke-MDE-DeviceLifecycle.ps1"
}
if (-not (Test-Path $lifecycleScript)) {
    Write-Error "[SCRIPT] Invoke-MDE-DeviceLifecycle.ps1 not found. Upload it alongside this runbook or as a module file."
}

Write-Output "[SCRIPT] Lifecycle engine: $lifecycleScript"

# ── Execute lifecycle engine ───────────────────────────────────────────────────
$reportPath = "$env:TEMP\mde-offboard-candidates-$(Get-Date -Format 'yyyyMMddHHmm').csv"

Write-Output "[RUN] Executing Invoke-MDE-DeviceLifecycle.ps1..."
& $lifecycleScript `
    -TenantId              $tenantId `
    -AppId                 $appId `
    -AppSecret             $appSecret `
    -ReportOnly            $ReportOnly `
    -DiasInativo7d         $DiasInativo7d `
    -DiasInativo40d        $DiasInativo40d `
    -HorasEfemero          $HorasEfemero `
    -UseAzureAutomation    $false `
    -UseManagedIdentity    $true `
    -AutoDiscoverSubs      $AutoDiscover `
    -OffboardCandidateReportPath $reportPath `
    -NotifyWebhookUrl      $WebhookUrl `
    -Verbose:$false

Write-Output ""
Write-Output "[DONE] Lifecycle runbook completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC"
if (Test-Path $reportPath) {
    $offboardCount = (Import-Csv $reportPath).Count
    Write-Output "[REPORT] Offboard candidates: $offboardCount — see CSV in runbook output"
}

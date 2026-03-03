<#
.SYNOPSIS
    Runbook-EntraSync.ps1 v2.0.0
    Azure Automation Runbook — MDE Entra ID Group Synchronization

.DESCRIPTION
    Azure Automation native wrapper for Invoke-EntraGroupSync.ps1.
    Designed to run hourly in Azure Automation with:
    - System-Assigned Managed Identity for Azure ARM + Graph API operations
    - Azure Automation Variables for MDE API credentials (for optional MDE validation)
    - Per-subscription Entra ID Security Group creation and membership sync
    - Automatic removal of stale members when VMs are deleted from Azure

    REQUIRED AUTOMATION VARIABLES:
    - MDEGovernance-TenantId   (plain text)
    - MDEGovernance-AppId      (plain text)
    - MDEGovernance-AppSecret  (encrypted)

    REQUIRED PERMISSIONS:
    - Managed Identity: Reader on all in-scope subscriptions
    - Managed Identity (Graph): Group.ReadWrite.All, Device.Read.All
#>

param(
    [bool]$ReportOnly          = $true,
    [bool]$CriarGruposPorSub   = $true,
    [string]$PrefixoGrupo      = "grp-mde-governance",
    [bool]$IncluirArc          = $true,
    [bool]$RemoverMembrosSemVm = $true,
    [bool]$AutoDiscover        = $true
)

$ErrorActionPreference = "Stop"
$runbookVersion = "2.0.0"

Write-Output "=============================================="
Write-Output "  MDE-DeviceGovernance Entra Sync Runbook"
Write-Output "  Version: $runbookVersion"
Write-Output "  Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC"
Write-Output "  Mode: $(if($ReportOnly){'REPORT-ONLY'}else{'LIVE - GROUP MEMBERSHIPS WILL BE UPDATED'})"
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
    Write-Error "[CREDS] Failed to load Automation Variables: $($_.Exception.Message)"
}

# ── Resolve entra sync script path ────────────────────────────────────────────
$entraScript = "$PSScriptRoot\..\02-Entra-Sync\Invoke-EntraGroupSync.ps1"
if (-not (Test-Path $entraScript)) {
    $entraScript = "$PSScriptRoot\Invoke-EntraGroupSync.ps1"
}
if (-not (Test-Path $entraScript)) {
    Write-Error "[SCRIPT] Invoke-EntraGroupSync.ps1 not found. Upload it alongside this runbook."
}

Write-Output "[SCRIPT] Entra Sync engine: $entraScript"

# ── Execute Entra sync ────────────────────────────────────────────────────────
Write-Output "[RUN] Executing Invoke-EntraGroupSync.ps1..."
& $entraScript `
    -TenantId              $tenantId `
    -AppId                 $appId `
    -AppSecret             $appSecret `
    -ReportOnly            $ReportOnly `
    -CriarGruposPorSub     $CriarGruposPorSub `
    -PrefixoGrupo          $PrefixoGrupo `
    -IncluirArc            $IncluirArc `
    -RemoverMembrosSemVm   $RemoverMembrosSemVm `
    -AutoDiscoverSubs      $AutoDiscover `
    -Verbose:$false

Write-Output ""
Write-Output "[DONE] Entra Sync runbook completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC"

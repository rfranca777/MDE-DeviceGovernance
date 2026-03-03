<#
.SYNOPSIS
    Set-MDEDeviceTag.ps1 v3.0.0
    MDE Device Governance — Registry-Based Device Tag Applier

.DESCRIPTION
    Sets the MDE device group tag via Windows registry key.
    Microsoft Defender for Endpoint reads this key and assigns the device to
    the corresponding group in security.microsoft.com.

    Registry path:
        HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging
    Value name: Group
    Value type: REG_SZ
    Value data: <DeviceTag>

    This script is designed to be deployed via:
    - Azure Policy (Custom Script Extension)
    - Azure Automation (Run Command on VM)
    - Direct execution with administrative rights

.PARAMETER DeviceTag
    Tag value to apply. If empty, uses the current Azure subscription display name
    (normalized: spaces -> hyphens, special chars stripped, max 128 chars).

.PARAMETER Force
    Apply even if a tag is already set (overwrite).

.PARAMETER ReportOnly
    Only report current tag value — do not modify registry.

.EXAMPLE
    .\Set-MDEDeviceTag.ps1 -DeviceTag "PROD-SUBSCRIPTION-1"
    .\Set-MDEDeviceTag.ps1 -ReportOnly
    .\Set-MDEDeviceTag.ps1 -Force -DeviceTag "rafaelluizf-1"
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Tag value to apply (max 128 chars). Empty = auto-detect from IMDS.")]
    [string]$DeviceTag = "",

    [Parameter(HelpMessage = "Overwrite existing tag if already set.")]
    [switch]$Force,

    [Parameter(HelpMessage = "Report current value only — do not modify.")]
    [switch]$ReportOnly
)

$ErrorActionPreference = "Stop"
$registryPath  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging"
$registryName  = "Group"
$maxTagLength  = 128
$scriptVersion = "3.0.0"

Write-Host "[MDE-DeviceGovernance] Set-MDEDeviceTag.ps1 v$scriptVersion" -ForegroundColor Cyan

# ── Verify OS ─────────────────────────────────────────────────────────────────
if (-not $IsWindows -and -not ($PSVersionTable.PSEdition -eq "Desktop")) {
    Write-Error "This script is Windows-only (sets HKLM registry key for MDE)."
}

# ── Report current value ───────────────────────────────────────────────────────
$currentValue = $null
try {
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryName -ErrorAction SilentlyContinue).$registryName
} catch {}

Write-Host "  Current tag: $(if($currentValue){"'$currentValue'"}else{'(not set)'})"

if ($ReportOnly) {
    Write-Host "  ReportOnly mode — no changes made." -ForegroundColor Yellow
    exit 0
}

# ── Determine tag value ────────────────────────────────────────────────────────
if (-not $DeviceTag) {
    Write-Host "  DeviceTag not specified — attempting auto-detection from Azure IMDS..." -ForegroundColor Gray
    try {
        $imds = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01" `
            -Headers @{Metadata="true"} -TimeoutSec 3
        $subName = $imds.subscriptionId  # Use ID as fallback
        if ($imds.PSObject.Properties.Name -contains "subscriptionId") {
            # Try to normalize subscription name from tags or use ID
            $DeviceTag = $imds.subscriptionId.Substring(0, [Math]::Min(32, $imds.subscriptionId.Length))
        }
        Write-Host "  Auto-detected tag from IMDS: '$DeviceTag'" -ForegroundColor Gray
    } catch {
        Write-Host "  IMDS not available — please provide -DeviceTag parameter." -ForegroundColor Yellow
        Write-Error "DeviceTag cannot be auto-detected (not running on Azure VM or IMDS not accessible)."
    }
}

# ── Normalize tag value ────────────────────────────────────────────────────────
$DeviceTag = $DeviceTag.Trim()
$DeviceTag = $DeviceTag -replace '[^\w\-\.]', '-'   # keep letters, digits, hyphens, dots
$DeviceTag = $DeviceTag -replace '-{2,}', '-'        # collapse multiple hyphens
$DeviceTag = $DeviceTag.TrimStart('-').TrimEnd('-')   # strip leading/trailing hyphens
if ($DeviceTag.Length -gt $maxTagLength) { $DeviceTag = $DeviceTag.Substring(0, $maxTagLength) }

if (-not $DeviceTag) { Write-Error "DeviceTag is empty after normalization. Provide a valid value." }

# ── Check if update needed ────────────────────────────────────────────────────
if ($currentValue -eq $DeviceTag -and -not $Force) {
    Write-Host "  Tag already set to '$DeviceTag' — no changes needed." -ForegroundColor Green
    exit 0
}

if ($currentValue -and $currentValue -ne $DeviceTag -and -not $Force) {
    Write-Host "  WARNING: Tag is already set to '$currentValue'. Use -Force to overwrite." -ForegroundColor Yellow
    exit 0
}

# ── Admin check ───────────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Administrator rights required to write HKLM registry."
}

# ── Apply tag ─────────────────────────────────────────────────────────────────
try {
    if (-not (Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
        Write-Host "  Registry path created: $registryPath" -ForegroundColor Gray
    }
    Set-ItemProperty -Path $registryPath -Name $registryName -Value $DeviceTag -Type String -Force
    $verify = (Get-ItemProperty -Path $registryPath -Name $registryName).$registryName
    if ($verify -eq $DeviceTag) {
        Write-Host "  SUCCESS: Tag '$DeviceTag' applied." -ForegroundColor Green
        Write-Host "  MDE will pick up the change within the next heartbeat (~30min)." -ForegroundColor Gray
        exit 0
    } else {
        Write-Error "Registry write succeeded but verification failed. Expected='$DeviceTag' Got='$verify'"
    }
} catch {
    Write-Error "Failed to write registry: $($_.Exception.Message)"
}

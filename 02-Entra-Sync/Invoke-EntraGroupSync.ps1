<#
.SYNOPSIS
    Invoke-EntraGroupSync.ps1 v2.0.0
    MDE Device Governance — Entra ID Group Sync (per subscription)

.DESCRIPTION
    Synchronizes Azure VMs and Azure Arc machines to Entra ID Security Groups,
    one group per Azure subscription. These groups are then linked to MDE Device Groups
    in the Microsoft Defender portal for dynamic device targeting.

    v2.0 improvements over PolicyAutomation v1.0:
    ✔ One Entra ID group per subscription (vs. one global group)
    ✔ Stale member removal (VMs deleted from Azure are removed from the group)
    ✔ Azure Arc machines support
    ✔ Works with Managed Identity OR client credentials
    ✔ Dry-run (reportOnly) mode
    ✔ Idempotent: create groups only if they don't exist
    ✔ Group naming: {prefixoGrupo}-{subNameShort}

    FLOW:
    1. Authenticate (MI or client_credentials)
    2. List all enabled Azure subscriptions
    3. For each subscription:
       a. Ensure Entra ID Security Group exists (create if needed)
       b. Get all Azure VMs + Arc machines (current state)
       c. Find matching Entra ID device objects (by displayName)
       d. Add missing devices to the group
       e. (if removerMembrosSemVm) Remove devices no longer in Azure from the group
    4. Report: groups created, members added/removed per subscription

.PARAMETER tenantId / appId / appSecret
    Azure AD credentials. Required unless UseAzureAutomation=$true.

.PARAMETER prefixoGrupo
    Prefix for Entra ID group names. Default: 'grp-mde-governance'.
    Result: 'grp-mde-governance-{subNameShort}'

.PARAMETER incluirArc
    Include Azure Arc machines. Default: $true.

.PARAMETER removerMembrosSemVm
    Remove group members whose VM no longer exists in Azure. Default: $true.

.PARAMETER reportOnly
    $true = dry-run, no changes. Default: $true.

.PARAMETER UseAzureAutomation / UseManagedIdentity
    Azure Automation native support (same as lifecycle engine).

.NOTES
    Version:  2.0.0
    Date:     2026-03-02
    Requires: Group.ReadWrite.All + Device.Read.All (Graph API)
              Reader on subscriptions (ARM)
#>

param (
    [Parameter(Mandatory=$false)] [string]   $tenantId,
    [Parameter(Mandatory=$false)] [string]   $appId,
    [Parameter(Mandatory=$false)] [string]   $appSecret,
    [Parameter(Mandatory=$false)] [string]   $prefixoGrupo       = "grp-mde-governance",
    [Parameter(Mandatory=$false)] [bool]     $incluirArc          = $true,
    [Parameter(Mandatory=$false)] [bool]     $removerMembrosSemVm = $true,
    [Parameter(Mandatory=$false)] [bool]     $reportOnly          = $true,
    [Parameter(Mandatory=$false)] [bool]     $UseAzureAutomation  = $false,
    [Parameter(Mandatory=$false)] [string]   $AaVarTenantId       = "MDEGovernance-TenantId",
    [Parameter(Mandatory=$false)] [string]   $AaVarAppId          = "MDEGovernance-AppId",
    [Parameter(Mandatory=$false)] [string]   $AaVarAppSecret      = "MDEGovernance-AppSecret",
    [Parameter(Mandatory=$false)] [bool]     $UseManagedIdentity  = $false,
    [Parameter(Mandatory=$false)] [string[]] $excludeSubscriptions = @()
)

$ErrorActionPreference = "Continue"
$script:Version  = "2.0.0"
$script:RunDate  = Get-Date -Format "yyyy-MM-dd_HH-mm"
$script:LogPath  = Join-Path $PSScriptRoot "EntraSync-Log-$($script:RunDate).log"
$script:ApiCalls = 0

# Token cache
$script:ArmToken    = $null; $script:ArmExpiry   = [datetime]::MinValue
$script:GraphToken  = $null; $script:GraphExpiry  = [datetime]::MinValue

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
    }
}

function Initialize-Credentials {
    if (-not $UseAzureAutomation) { return }
    try {
        if ([string]::IsNullOrWhiteSpace($script:t)) { $script:t = Get-AutomationVariable -Name $AaVarTenantId }
        if ([string]::IsNullOrWhiteSpace($script:a)) { $script:a = Get-AutomationVariable -Name $AaVarAppId    }
        if ([string]::IsNullOrWhiteSpace($script:s)) { $script:s = Get-AutomationVariable -Name $AaVarAppSecret}
        Write-Log "AA Variables loaded" -Level OK
    }
    catch { Write-Log "Failed to load AA Variables: $($_.Exception.Message)" -Level ERROR; throw }
}

function Get-OAuth2Token {
    param ([string]$TenantId, [string]$AppId, [string]$AppSecret, [string]$Scope)
    $body = @{ client_id=$AppId; client_secret=$AppSecret; grant_type="client_credentials"; scope=$Scope }
    $r    = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
                -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
    return @{ Token = $r.access_token; Expiry = (Get-Date).AddSeconds($r.expires_in - 120) }
}

function Get-MIToken {
    param ([string]$Resource)
    $headers  = @{ "Metadata" = "true" }
    $uri      = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$([System.Uri]::EscapeDataString($Resource))"
    $r        = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -TimeoutSec 10 -ErrorAction Stop
    return @{ Token = $r.access_token; Expiry = (Get-Date).AddSeconds([int]$r.expires_in - 120) }
}

function Get-ArmToken {
    if ($script:ArmToken -and (Get-Date) -lt $script:ArmExpiry) { return $script:ArmToken }
    if ($UseManagedIdentity) {
        try {
            $result = Get-MIToken -Resource "https://management.azure.com/"
            $script:ArmToken = $result.Token; $script:ArmExpiry = $result.Expiry
            Write-Log "ARM Token via Managed Identity obtained" -Level OK
            return $script:ArmToken
        } catch { Write-Log "IMDS unavailable: $($_.Exception.Message)" -Level WARN }
    }
    $result = Get-OAuth2Token -TenantId $script:t -AppId $script:a -AppSecret $script:s `
                              -Scope "https://management.azure.com/.default"
    $script:ArmToken = $result.Token; $script:ArmExpiry = $result.Expiry
    Write-Log "ARM Token (client_creds) obtained" -Level OK
    return $script:ArmToken
}

function Get-GraphToken {
    if ($script:GraphToken -and (Get-Date) -lt $script:GraphExpiry) { return $script:GraphToken }
    $result = Get-OAuth2Token -TenantId $script:t -AppId $script:a -AppSecret $script:s `
                              -Scope "https://graph.microsoft.com/.default"
    $script:GraphToken = $result.Token; $script:GraphExpiry = $result.Expiry
    Write-Log "Graph Token obtained" -Level OK
    return $script:GraphToken
}

function Invoke-GraphApi {
    param ([string]$Uri, [string]$Method = "Get", [string]$Body = $null)
    $all = @(); $url = $Uri
    do {
        $headers = @{ Authorization = "Bearer $(Get-GraphToken)"; "Content-Type" = "application/json" }
        $params  = @{ Uri=$url; Headers=$headers; Method=$Method; ErrorAction="Stop" }
        if ($Body) { $params.Body = $Body }
        $resp    = Invoke-RestMethod @params; $script:ApiCalls++
        if ($resp.value) { $all += $resp.value } elseif ($Method -eq "Get") { $all += $resp } else { return $resp }
        $url = $resp.'@odata.nextLink'
    } while ($url)
    return $all
}

function Invoke-ArmApi {
    param ([string]$Uri)
    $headers = @{ Authorization = "Bearer $(Get-ArmToken)"; "Content-Type" = "application/json" }
    $all = @(); $url = $Uri
    do {
        $resp = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop; $script:ApiCalls++
        if ($resp.value) { $all += $resp.value } else { $all += $resp }
        $url = $resp.nextLink
    } while ($url)
    return $all
}

function ConvertTo-GroupName {
    param ([string]$SubscriptionName, [string]$Prefix)
    $clean = $SubscriptionName -replace '[^a-zA-Z0-9-]','-' -replace '--+','-' -replace '^-|-$',''
    $short = $clean.Substring(0,[Math]::Min(40,$clean.Length)).ToLower()
    return "$Prefix-$short"
}

function Get-OrCreateEntraGroup {
    param ([string]$GroupName, [string]$Description)

    $filter   = "displayName eq '$GroupName'"
    $existing = Invoke-GraphApi -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=$([System.Uri]::EscapeDataString($filter))"
    if ($existing -and $existing.Count -gt 0) {
        Write-Log "  Group exists: $GroupName (ID: $($existing[0].id))" -Level OK
        return $existing[0].id
    }

    if ($reportOnly) {
        Write-Log "  [REPORT-ONLY] Would create group: $GroupName" -Level WARN
        return $null
    }

    $mailNick = ($GroupName -replace '[^a-zA-Z0-9]','').Substring(0,[Math]::Min(64,($GroupName -replace '[^a-zA-Z0-9]','').Length))
    if (-not $mailNick) { $mailNick = "mdegroup" + (Get-Random -Maximum 9999) }

    $body = @{
        displayName      = $GroupName
        mailNickname     = $mailNick
        mailEnabled      = $false
        securityEnabled  = $true
        description      = $Description
    } | ConvertTo-Json

    $resp = Invoke-GraphApi -Uri "https://graph.microsoft.com/v1.0/groups" -Method Post -Body $body
    if ($resp -and $resp.id) {
        Write-Log "  Group CREATED: $GroupName (ID: $($resp.id))" -Level OK
        return $resp.id
    }
    Write-Log "  Failed to create group: $GroupName" -Level ERROR
    return $null
}

function Get-AzureDeviceNames {
    param ([string]$SubscriptionId, [bool]$IncludeArc)

    $names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    # Azure VMs
    try {
        $vms = Invoke-ArmApi -Uri "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Compute/virtualMachines?api-version=2023-03-01"
        foreach ($vm in $vms) { if ($vm.name) { $null = $names.Add($vm.name) } }
        Write-Log "  VMs in sub ${SubscriptionId}: $($vms.Count)" -Level DEBUG
    }
    catch { Write-Log "  Warning: Could not list VMs in subscription ${SubscriptionId}: $($_.Exception.Message)" -Level WARN }

    # Azure Arc machines
    if ($IncludeArc) {
        try {
            $arc = Invoke-ArmApi -Uri "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.HybridCompute/machines?api-version=2022-12-27"
            foreach ($m in $arc) { if ($m.name) { $null = $names.Add($m.name) } }
            Write-Log "  Arc machines in sub ${SubscriptionId}: $($arc.Count)" -Level DEBUG
        }
        catch { Write-Log "  Note: No Arc machines or module unavailable in subscription $SubscriptionId" -Level DEBUG }
    }

    return $names
}

function Sync-GroupMembers {
    param ([string]$GroupId, [string]$GroupName, [System.Collections.Generic.HashSet[string]]$AzureDeviceNames)

    # Get all Entra ID device objects matching Azure names
    Write-Log "  Retrieving Entra ID devices for matching..." -Level DEBUG
    $allEntraDevices = Invoke-GraphApi -Uri "https://graph.microsoft.com/v1.0/devices?`$select=id,displayName,deviceId"
    Write-Log "  Entra ID total devices: $($allEntraDevices.Count)" -Level DEBUG

    # Build name→id map for Entra devices
    $entraMap = @{}
    foreach ($d in $allEntraDevices) {
        if ($d.displayName) { $entraMap[$d.displayName.ToLower()] = $d.id }
    }

    # Match Azure devices to Entra IDs
    $targetIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($vmName in $AzureDeviceNames) {
        $entraId = $entraMap[$vmName.ToLower()]
        if ($entraId) { $null = $targetIds.Add($entraId) }
        else { Write-Log "  Not in Entra ID (not registered yet?): $vmName" -Level DEBUG }
    }
    Write-Log "  Azure devices: $($AzureDeviceNames.Count) | Matched in Entra: $($targetIds.Count)" -Level INFO

    # Get current group members
    $currentMembers = Invoke-GraphApi -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId/members?`$select=id,displayName"
    $currentIds     = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($m in $currentMembers) { if ($m.id) { $null = $currentIds.Add($m.id) } }
    Write-Log "  Current group members: $($currentIds.Count)" -Level DEBUG

    # Devices to ADD
    $toAdd    = @($targetIds | Where-Object { -not $currentIds.Contains($_) })
    # Devices to REMOVE (in group but VM no longer in Azure)
    $toRemove = @()
    if ($removerMembrosSemVm) {
        $toRemove = @($currentIds | Where-Object { -not $targetIds.Contains($_) })
    }

    Write-Log "  To add: $($toAdd.Count) | To remove: $($toRemove.Count)" -Level INFO

    $added = 0; $removed = 0; $errors = 0

    if (-not $reportOnly) {
        # ADD members
        foreach ($id in $toAdd) {
            try {
                $body = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/devices/$id" } | ConvertTo-Json
                Invoke-GraphApi -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId/members/`$ref" -Method Post -Body $body | Out-Null
                $added++
                Write-Log "  + Added device $id to $GroupName" -Level OK
            }
            catch {
                if ($_.Exception.Message -match '409|already exists') {
                    $added++  # already member
                } else {
                    $errors++
                    Write-Log "  ERROR adding ${id}: $($_.Exception.Message)" -Level WARN
                }
            }
            Start-Sleep -Milliseconds 300
        }

        # REMOVE stale members
        foreach ($id in $toRemove) {
            try {
                Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId/members/$id/`$ref" `
                    -Method Delete `
                    -Headers @{ Authorization = "Bearer $(Get-GraphToken)" } `
                    -ErrorAction Stop | Out-Null
                $removed++
                Write-Log "  - Removed stale device $id from $GroupName" -Level WARN
            }
            catch {
                $errors++
                Write-Log "  ERROR removing ${id}: $($_.Exception.Message)" -Level WARN
            }
            Start-Sleep -Milliseconds 300
        }
    }
    else {
        foreach ($id in $toAdd)    { Write-Log "  [REPORT-ONLY] Would ADD: $id to $GroupName" -Level INFO }
        foreach ($id in $toRemove) { Write-Log "  [REPORT-ONLY] Would REMOVE: $id from $GroupName (stale)" -Level WARN }
        $added   = $toAdd.Count
        $removed = $toRemove.Count
    }

    return @{ Added = $added; Removed = $removed; Errors = $errors }
}

# ── MAIN ──────────────────────────────────────────────────────────────────
try {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║  MDE Governance — Entra Group Sync v$($script:Version)     ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    if ($reportOnly) { Write-Host "  [REPORT-ONLY] No changes will be made." -ForegroundColor Green }
    else             { Write-Host "  [LIVE MODE] Groups will be created/updated!" -ForegroundColor Yellow }
    Write-Host ""

    # Initialize credentials
    $script:t = $tenantId; $script:a = $appId; $script:s = $appSecret
    Initialize-Credentials
    if ([string]::IsNullOrWhiteSpace($script:t)) { throw "tenantId required" }

    # Get all subscriptions
    Write-Log "=== Getting subscriptions from ARM ===" -Level INFO
    $allSubs  = Invoke-ArmApi -Uri "https://management.azure.com/subscriptions?api-version=2020-01-01"
    $enabled  = @($allSubs | Where-Object { $_.state -eq "Enabled" })
    $excluded = @($excludeSubscriptions | ForEach-Object { $_.ToLower() })
    $filtered = @($enabled | Where-Object { $_.subscriptionId.ToLower() -notin $excluded })
    Write-Log "Subscriptions: $($enabled.Count) enabled, $($filtered.Count) in scope" -Level INFO

    $totalAdded   = 0; $totalRemoved = 0; $totalErrors = 0
    $syncResults  = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($sub in $filtered) {
        Write-Log "── Subscription: $($sub.displayName) ($($sub.subscriptionId)) ──" -Level INFO

        $groupName = ConvertTo-GroupName -SubscriptionName $sub.displayName -Prefix $prefixoGrupo
        $groupDesc = "MDE Device Governance group for subscription: $($sub.displayName). Managed by Invoke-EntraGroupSync.ps1"

        # Create/get Entra group
        $groupId = Get-OrCreateEntraGroup -GroupName $groupName -Description $groupDesc
        if (-not $groupId -and $reportOnly) {
            Write-Log "  Skipping member sync (report-only, group not created)" -Level WARN
            continue
        }
        if (-not $groupId) { Write-Log "  Could not get/create group for $($sub.displayName)" -Level ERROR; continue }

        # Get Azure devices (VMs + Arc)
        $azureDevices = Get-AzureDeviceNames -SubscriptionId $sub.subscriptionId -IncludeArc $incluirArc

        if ($azureDevices.Count -eq 0) {
            Write-Log "  No Azure devices found in subscription $($sub.displayName)" -Level WARN
            continue
        }

        # Sync members
        $r = Sync-GroupMembers -GroupId $groupId -GroupName $groupName -AzureDeviceNames $azureDevices
        $totalAdded   += $r.Added
        $totalRemoved += $r.Removed
        $totalErrors  += $r.Errors

        $syncResults.Add([PSCustomObject]@{
            Subscription = $sub.displayName
            SubscriptionId = $sub.subscriptionId
            GroupName    = $groupName
            GroupId      = $groupId
            AzureDevices = $azureDevices.Count
            Added        = $r.Added
            Removed      = $r.Removed
            Errors       = $r.Errors
        })
    }

    # Summary
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  Entra Group Sync — Summary              ║" -ForegroundColor Cyan
    Write-Host "║  Mode: $(if($reportOnly){'REPORT-ONLY'.PadRight(34)}else{'LIVE'.PadRight(34)})║" -ForegroundColor $(if($reportOnly){"Green"}else{"Yellow"})
    Write-Host "╠══════════════════════════════════════════╣" -ForegroundColor Cyan
    foreach ($r in $syncResults) {
        Write-Host "║  Sub: $($r.Subscription.Substring(0,[Math]::Min(30,$r.Subscription.Length)).PadRight(34))║" -ForegroundColor White
        Write-Host "║    Group: $($r.GroupName.Substring(0,[Math]::Min(30,$r.GroupName.Length)).PadRight(30))║" -ForegroundColor Gray
        Write-Host "║    VMs: $("{0,3}" -f $r.AzureDevices) | +$("{0,3}" -f $r.Added) added | -$("{0,3}" -f $r.Removed) removed    ║" -ForegroundColor White
    }
    Write-Host "╠══════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║  Total: +$totalAdded added, -$totalRemoved removed, $totalErrors err  ║" -ForegroundColor White
    Write-Host "║  API calls: $script:ApiCalls                              ║" -ForegroundColor Gray
    Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Cyan

    Write-Log "Entra Group Sync completed. Added=$totalAdded, Removed=$totalRemoved, Errors=$totalErrors" -Level OK
}
catch {
    Write-Log "FATAL: $($_.Exception.Message)" -Level ERROR; throw
}
finally {
    Write-Host "### Entra Sync completed — $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ###" -ForegroundColor Green
}

<#
.SYNOPSIS
    Deploy-MDE-DeviceGovernance.ps1 v3.0.0
    MDE Device Governance — 16-Stage Azure Infrastructure Deployer

.DESCRIPTION
    Provisions all Azure infrastructure required for automated MDE Device Governance
    running entirely in the cloud via Azure Automation + Managed Identity.
    Zero secrets stored in code — all credentials in Azure Automation Variables.

    STAGES:
    01  Authentication (Azure CLI + MDE token validation)
    02  Naming convention + subscription selection
    03  Resource Group
    04  Entra ID Security Groups (one per subscription discovered)
    05  Azure Automation Account
    06  System-Assigned Managed Identity (enable on AA)
    07  RBAC — Reader on all in-scope subscriptions
    08  Microsoft Graph Permissions (Group.ReadWrite.All + Device.Read.All)
    09  Az.Accounts + Microsoft.Graph PowerShell modules in AA
    10  Runbook-Lifecycle (upload + publish)
    11  Runbook-EntraSync (upload + publish)
    12  Runbook-Lifecycle daily schedule
    13  Runbook-EntraSync hourly schedule
    14  Azure Policy (DeployIfNotExists — MDE device tag via registry)
    15  Azure Automation Variables (TenantId, AppId, AppSecret)
    16  Device Groups setup guide + HTML report

    REQUIRES:
    - Azure CLI (az) authenticated: az login
    - Current user: Owner/Contributor on target subscription(s)
    - Microsoft Graph perms to grant delegated permissions (Global Admin or Privileged Role Admin)
    - App Registration with Machine.ReadWrite.All on MDE API (already created manually)
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage="Skip stages already completed (CSV: '3,4,5')")]
    [string]$SkipStages = "",

    [Parameter(HelpMessage="Run all stages without prompting for confirmation per stage")]
    [switch]$AutoApprove,

    [Parameter(HelpMessage="Only display plan — do not create anything")]
    [switch]$PlanOnly,

    [Parameter(HelpMessage="Path to config.json (defaults to project root)")]
    [string]$ConfigPath = ""
)

$ErrorActionPreference = "Stop"
$scriptRoot = $PSScriptRoot
$projectRoot = Split-Path $scriptRoot -Parent

# ── Resolve config ─────────────────────────────────────────────────────────────
if (-not $ConfigPath) { $ConfigPath = Join-Path $projectRoot "config.json" }
if (-not (Test-Path $ConfigPath)) { Write-Error "config.json not found: $ConfigPath"; exit 1 }
$cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json

# ── Helpers ───────────────────────────────────────────────────────────────────
$stagesSkip = if ($SkipStages) { $SkipStages.Split(',') | ForEach-Object { $_.Trim() } } else { @() }
$stageStatus = @{}
$summary     = [System.Collections.Generic.List[PSObject]]::new()
$startTime   = Get-Date

function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║   MDE Device Governance — Azure Infrastructure Deployer v3.0    ║" -ForegroundColor Cyan
    Write-Host "  ║   16-Stage Full Deployment                                       ║" -ForegroundColor Cyan
    Write-Host "  ╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Stage {
    param([int]$n, [string]$name, [string]$desc="")
    $pad = $n.ToString("D2")
    Write-Host ""
    Write-Host "  ┌── STAGE $pad : $name ──────────────────────────" -ForegroundColor Yellow
    if ($desc) { Write-Host "  │  $desc" -ForegroundColor Gray }
}

function Write-StageOk  { param([string]$msg) Write-Host "  │  OK: $msg" -ForegroundColor Green }
function Write-StageWarn{ param([string]$msg) Write-Host "  │  WARN: $msg" -ForegroundColor Yellow }
function Write-StageInfo{ param([string]$msg) Write-Host "  │  INFO: $msg" -ForegroundColor Gray }
function Write-StageFail{ param([string]$msg) Write-Host "  │  FAIL: $msg" -ForegroundColor Red }

function Confirm-Stage {
    param([int]$n)
    if ($AutoApprove -or $PlanOnly) { return $true }
    Write-Host "  │  Continue with Stage $n? (S=sim / N=pular / X=abortar): " -ForegroundColor White -NoNewline
    $r = Read-Host
    if ($r -match '^[Xx]') { Write-Host "  Deployment aborted by user." -ForegroundColor Red; exit 0 }
    return ($r -match '^[Ss]$' -or $r -eq "")
}

function Should-RunStage { param([int]$n) return $stagesSkip -notcontains $n.ToString() }

function Add-Summary {
    param([int]$n, [string]$name, [string]$status, [string]$detail="")
    $summary.Add([PSCustomObject]@{Stage=$n; Name=$name; Status=$status; Detail=$detail})
}

Write-Banner

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 01: Authentication
# ──────────────────────────────────────────────────────────────────────────────
Write-Stage 1 "Authentication" "Validate Azure CLI session + MDE App Registration connectivity"
if (Should-RunStage 1) {
    $proceed = Confirm-Stage 1
    if ($proceed -and -not $PlanOnly) {
        try {
            $acctJson = az account show --output json 2>$null | ConvertFrom-Json
            if (-not $acctJson) { Write-Error "Not logged in to Azure CLI. Run: az login" }
            Write-StageOk "Azure CLI: $($acctJson.user.name) | Sub: $($acctJson.name)"

            if ($cfg.autenticacao.tenantId -like "<*>") {
                Write-StageWarn "config.json placeholders detected — credentials must be filled before Stage 15"
            } else {
                # Quick token validation
                $body = @{
                    grant_type    = "client_credentials"
                    client_id     = $cfg.autenticacao.appId
                    client_secret = $cfg.autenticacao.appSecret
                    scope         = "https://api.securitycenter.microsoft.com/.default"
                }
                try {
                    $tokenResp = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$($cfg.autenticacao.tenantId)/oauth2/v2.0/token" -Body $body -ContentType "application/x-www-form-urlencoded" -TimeoutSec 15
                    Write-StageOk "MDE App Registration token obtained successfully"
                } catch {
                    Write-StageWarn "Could not validate MDE token: $($_.Exception.Message)"
                }
            }
            Add-Summary 1 "Authentication" "OK" $acctJson.name
        } catch { Write-StageFail $_.Exception.Message; Add-Summary 1 "Authentication" "FAIL" $_.Exception.Message }
    } else { Add-Summary 1 "Authentication" "SKIPPED" }
}

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 02: Naming + Subscription Selection
# ──────────────────────────────────────────────────────────────────────────────
Write-Stage 2 "Naming + Subscription Selection" "Define resource names and select target subscription"
if (Should-RunStage 2) {
    $proceed = Confirm-Stage 2

    if ($proceed -and -not $PlanOnly) {
        $subs = az account list --output json | ConvertFrom-Json | Where-Object { $_.state -eq "Enabled" }
        Write-StageInfo "Available subscriptions:"
        for ($i = 0; $i -lt $subs.Count; $i++) {
            Write-Host "    [$i] $($subs[$i].name) ($($subs[$i].id))" -ForegroundColor White
        }
        Write-Host "  Select subscription index for deploying AA/RG infrastructure: " -ForegroundColor Cyan -NoNewline
        $idx = [int](Read-Host)
        $global:targetSub = $subs[$idx]
        az account set --subscription $global:targetSub.id | Out-Null
        Write-StageOk "Selected: $($global:targetSub.name)"

        Write-Host "  Location (default=eastus2): " -ForegroundColor Cyan -NoNewline
        $locInput = Read-Host
        $global:location = if ($locInput) { $locInput } else { "eastus2" }

        # Naming convention
        $global:baseName    = "mde-governance"
        $global:rgName      = "rg-$global:baseName"
        $global:aaName      = "aa-$global:baseName"
        $global:policyName  = "policy-$global:baseName-device-tag"
        $global:miPrincipal = $null  # filled in stage 6

        Write-StageInfo "RG:     $global:rgName"
        Write-StageInfo "AA:     $global:aaName"
        Write-StageInfo "Policy: $global:policyName"
        Write-StageInfo "Region: $global:location"
        Add-Summary 2 "Naming" "OK" "RG=$global:rgName AA=$global:aaName"
    } else { Add-Summary 2 "Naming" "SKIPPED" }
}

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 03: Resource Group
# ──────────────────────────────────────────────────────────────────────────────
Write-Stage 3 "Resource Group" "Create $global:rgName"
if (Should-RunStage 3) {
    $proceed = Confirm-Stage 3
    if ($proceed -and -not $PlanOnly) {
        try {
            $rgExists = az group exists --name $global:rgName --output tsv
            if ($rgExists -eq "true") {
                Write-StageWarn "Resource Group '$global:rgName' already exists — reusing"
            } else {
                az group create --name $global:rgName --location $global:location --tags "project=mde-device-governance" "version=3.0.0" --output none
                Write-StageOk "Resource Group '$global:rgName' created in $global:location"
            }
            Add-Summary 3 "Resource Group" "OK" $global:rgName
        } catch { Write-StageFail $_.Exception.Message; Add-Summary 3 "Resource Group" "FAIL" $_.Exception.Message }
    } else { Add-Summary 3 "Resource Group" "SKIPPED" }
}

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 04: Entra ID Security Groups
# ──────────────────────────────────────────────────────────────────────────────
Write-Stage 4 "Entra ID Security Groups" "One group per in-scope subscription (prefix: $($cfg.entraSync.prefixoGrupo))"
if (Should-RunStage 4) {
    $proceed = Confirm-Stage 4
    if ($proceed -and -not $PlanOnly) {
        try {
            $inScopeSubs = @()
            if ($cfg.descoberta.autoDiscoverSubscriptions) {
                $allSubs = az account list --all --output json | ConvertFrom-Json | Where-Object { $_.state -eq "Enabled" }
                $excluded = $cfg.descoberta.excluirSubscriptions
                $inScopeSubs = $allSubs | Where-Object { $excluded -notcontains $_.id }
            } else {
                $csvPath = Join-Path $projectRoot ($cfg.caminhos.subscriptionMappingCsv -replace '^\.\\',"")
                $inScopeSubs = Import-Csv $csvPath -Delimiter ";" | ForEach-Object {
                    [PSCustomObject]@{id=$_.subscriptionId; name=$_.subscriptionName}
                }
            }

            $prefix = $cfg.entraSync.prefixoGrupo
            foreach ($sub in $inScopeSubs) {
                $shortName = ($sub.name -replace 'ME-MngEnvMCAP\d+-[^-]+-','') -replace '[^a-zA-Z0-9-]','-'
                if ($shortName.Length -gt 20) { $shortName = $shortName.Substring(0,20) }
                $groupName = "$prefix-$shortName"
                $existing = az ad group list --filter "displayName eq '$groupName'" --output json | ConvertFrom-Json
                if ($existing.Count -eq 0) {
                    az ad group create --display-name $groupName --mail-nickname ($groupName -replace '-','') --description "MDE Device Governance — Subscription: $($sub.name)" --output none
                    Write-StageOk "Created group: $groupName"
                } else {
                    Write-StageWarn "Group already exists: $groupName (id=$($existing[0].id))"
                }
            }
            Add-Summary 4 "Entra ID Groups" "OK" "$($inScopeSubs.Count) subscription(s)"
        } catch { Write-StageFail $_.Exception.Message; Add-Summary 4 "Entra ID Groups" "FAIL" $_.Exception.Message }
    } else { Add-Summary 4 "Entra ID Groups" "SKIPPED" }
}

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 05: Azure Automation Account
# ──────────────────────────────────────────────────────────────────────────────
Write-Stage 5 "Azure Automation Account" "Create $global:aaName"
if (Should-RunStage 5) {
    $proceed = Confirm-Stage 5
    if ($proceed -and -not $PlanOnly) {
        try {
            $aaExists = az automation account show --resource-group $global:rgName --name $global:aaName --output json 2>$null | ConvertFrom-Json
            if ($aaExists) {
                Write-StageWarn "Automation Account '$global:aaName' already exists"
            } else {
                az automation account create --resource-group $global:rgName --name $global:aaName --location $global:location --sku Free --output none
                Write-StageOk "Automation Account '$global:aaName' created"
            }
            Add-Summary 5 "Automation Account" "OK" $global:aaName
        } catch { Write-StageFail $_.Exception.Message; Add-Summary 5 "Automation Account" "FAIL" $_.Exception.Message }
    } else { Add-Summary 5 "Automation Account" "SKIPPED" }
}

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 06: Managed Identity
# ──────────────────────────────────────────────────────────────────────────────
Write-Stage 6 "Managed Identity" "Enable System-Assigned MI on Automation Account"
if (Should-RunStage 6) {
    $proceed = Confirm-Stage 6
    if ($proceed -and -not $PlanOnly) {
        try {
            $aaObj = az automation account show --resource-group $global:rgName --name $global:aaName --output json | ConvertFrom-Json
            $miId  = $aaObj.identity.principalId
            if (-not $miId) {
                az automation account update --resource-group $global:rgName --name $global:aaName --assign-identity '[system]' --output none
                Start-Sleep -Seconds 5
                $aaObj = az automation account show --resource-group $global:rgName --name $global:aaName --output json | ConvertFrom-Json
                $miId  = $aaObj.identity.principalId
            }
            $global:miPrincipal = $miId
            Write-StageOk "Managed Identity principal: $global:miPrincipal"
            Add-Summary 6 "Managed Identity" "OK" $global:miPrincipal
        } catch { Write-StageFail $_.Exception.Message; Add-Summary 6 "Managed Identity" "FAIL" $_.Exception.Message }
    } else { Add-Summary 6 "Managed Identity" "SKIPPED" }
}

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 07: RBAC — Reader on in-scope subscriptions
# ──────────────────────────────────────────────────────────────────────────────
Write-Stage 7 "RBAC — Reader" "Assign Reader to MI on all in-scope subscriptions"
if (Should-RunStage 7) {
    $proceed = Confirm-Stage 7
    if ($proceed -and -not $PlanOnly) {
        try {
            if (-not $global:miPrincipal) { throw "Managed Identity principal not set. Run/complete Stage 6 first." }
            $allSubs = az account list --all --output json | ConvertFrom-Json | Where-Object { $_.state -eq "Enabled" }
            $excluded = $cfg.descoberta.excluirSubscriptions
            $inScopeSubs = $allSubs | Where-Object { $excluded -notcontains $_.id }
            foreach ($sub in $inScopeSubs) {
                $scope = "/subscriptions/$($sub.id)"
                az role assignment create --assignee $global:miPrincipal --role "Reader" --scope $scope --output none 2>$null
                Write-StageOk "Reader assigned on: $($sub.name)"
            }
            Add-Summary 7 "RBAC Reader" "OK" "$($inScopeSubs.Count) subscriptions"
        } catch { Write-StageFail $_.Exception.Message; Add-Summary 7 "RBAC Reader" "FAIL" $_.Exception.Message }
    } else { Add-Summary 7 "RBAC Reader" "SKIPPED" }
}

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 08: Graph API Permissions
# ──────────────────────────────────────────────────────────────────────────────
Write-Stage 8 "Graph API Permissions" "Grant Group.ReadWrite.All + Device.Read.All to MI"
if (Should-RunStage 8) {
    $proceed = Confirm-Stage 8
    if ($proceed -and -not $PlanOnly) {
        try {
            if (-not $global:miPrincipal) { throw "Managed Identity principal not set." }
            $graphAppId = "00000003-0000-0000-c000-000000000000"
            $graphSp    = az ad sp show --id $graphAppId --output json | ConvertFrom-Json
            $rolesNeeded = @(
                @{Name="Group.ReadWrite.All";   Id=($graphSp.appRoles | Where-Object { $_.value -eq "Group.ReadWrite.All" }).id}
                @{Name="Device.Read.All";       Id=($graphSp.appRoles | Where-Object { $_.value -eq "Device.Read.All"      }).id}
            )
            $miSp = az ad sp show --id $global:miPrincipal --output json 2>$null | ConvertFrom-Json
            foreach ($role in $rolesNeeded) {
                if (-not $role.Id) { Write-StageWarn "Role ID not found for: $($role.Name) — skipping"; continue }
                $body = @{ principalId=$global:miPrincipal; resourceId=$graphSp.id; appRoleId=$role.Id } | ConvertTo-Json
                $existing = az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals/$global:miPrincipal/appRoleAssignments" --output json | ConvertFrom-Json
                $alreadyAssigned = $existing.value | Where-Object { $_.appRoleId -eq $role.Id }
                if ($alreadyAssigned) {
                    Write-StageWarn "$($role.Name) already assigned"
                } else {
                    az rest --method POST --url "https://graph.microsoft.com/v1.0/servicePrincipals/$global:miPrincipal/appRoleAssignments" --body $body --headers "Content-Type=application/json" --output none
                    Write-StageOk "Granted: $($role.Name)"
                }
            }
            Add-Summary 8 "Graph Permissions" "OK" "Group.ReadWrite.All + Device.Read.All"
        } catch { Write-StageFail $_.Exception.Message; Add-Summary 8 "Graph Permissions" "FAIL" $_.Exception.Message }
    } else { Add-Summary 8 "Graph Permissions" "SKIPPED" }
}

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 09: PowerShell Modules in AA
# ──────────────────────────────────────────────────────────────────────────────
Write-Stage 9 "Modules" "Import Az.Accounts + Microsoft.Graph.Groups into Automation Account"
if (Should-RunStage 9) {
    $proceed = Confirm-Stage 9
    if ($proceed -and -not $PlanOnly) {
        $modules = @(
            @{Name="Az.Accounts";         Version=""; Uri="https://www.powershellgallery.com/packages/Az.Accounts/"}
            @{Name="Microsoft.Graph.Authentication"; Version=""; Uri="https://www.powershellgallery.com/packages/Microsoft.Graph.Authentication/"}
            @{Name="Microsoft.Graph.Groups"; Version=""; Uri="https://www.powershellgallery.com/packages/Microsoft.Graph.Groups/"}
            @{Name="Microsoft.Graph.Users";  Version=""; Uri="https://www.powershellgallery.com/packages/Microsoft.Graph.Users/"}
        )
        foreach ($mod in $modules) {
            try {
                $existing = az automation module show --resource-group $global:rgName --automation-account-name $global:aaName --name $mod.Name --output json 2>$null | ConvertFrom-Json
                if ($existing -and $existing.provisioningState -eq "Succeeded") {
                    Write-StageWarn "Module $($mod.Name) already imported"
                } else {
                    az automation module create --resource-group $global:rgName --automation-account-name $global:aaName --name $mod.Name --content-link "$($mod.Uri)" --output none
                    Write-StageOk "Module $($mod.Name) import initiated (async — check portal for status)"
                }
            } catch { Write-StageWarn "Module $($mod.Name): $($_.Exception.Message)" }
        }
        Write-StageInfo "NOTE: Module import is async. Runbooks (stages 10-11) may take 5-15min to be runnable."
        Add-Summary 9 "Modules" "OK (async)" "Az.Accounts, Microsoft.Graph.*"
    } else { Add-Summary 9 "Modules" "SKIPPED" }
}

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 10: Runbook — Lifecycle
# ──────────────────────────────────────────────────────────────────────────────
Write-Stage 10 "Runbook Lifecycle" "Upload + publish Runbook-Lifecycle.ps1"
if (Should-RunStage 10) {
    $proceed = Confirm-Stage 10
    if ($proceed -and -not $PlanOnly) {
        try {
            $rbPath = Join-Path $projectRoot "06-Runbooks\Runbook-Lifecycle.ps1"
            if (-not (Test-Path $rbPath)) { throw "Runbook-Lifecycle.ps1 not found: $rbPath" }
            $rbName = "MDE-DeviceGovernance-Lifecycle"
            az automation runbook create --resource-group $global:rgName --automation-account-name $global:aaName --name $rbName --type "PowerShell" --output none 2>$null
            az automation runbook replace-content --resource-group $global:rgName --automation-account-name $global:aaName --name $rbName --content "@$rbPath" --output none
            az automation runbook publish --resource-group $global:rgName --automation-account-name $global:aaName --name $rbName --output none
            Write-StageOk "Runbook '$rbName' uploaded and published"
            Add-Summary 10 "Runbook Lifecycle" "OK" $rbName
        } catch { Write-StageFail $_.Exception.Message; Add-Summary 10 "Runbook Lifecycle" "FAIL" $_.Exception.Message }
    } else { Add-Summary 10 "Runbook Lifecycle" "SKIPPED" }
}

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 11: Runbook — Entra Sync
# ──────────────────────────────────────────────────────────────────────────────
Write-Stage 11 "Runbook Entra Sync" "Upload + publish Runbook-EntraSync.ps1"
if (Should-RunStage 11) {
    $proceed = Confirm-Stage 11
    if ($proceed -and -not $PlanOnly) {
        try {
            $rbPath = Join-Path $projectRoot "06-Runbooks\Runbook-EntraSync.ps1"
            if (-not (Test-Path $rbPath)) { throw "Runbook-EntraSync.ps1 not found: $rbPath" }
            $rbName = "MDE-DeviceGovernance-EntraSync"
            az automation runbook create --resource-group $global:rgName --automation-account-name $global:aaName --name $rbName --type "PowerShell" --output none 2>$null
            az automation runbook replace-content --resource-group $global:rgName --automation-account-name $global:aaName --name $rbName --content "@$rbPath" --output none
            az automation runbook publish --resource-group $global:rgName --automation-account-name $global:aaName --name $rbName --output none
            Write-StageOk "Runbook '$rbName' uploaded and published"
            Add-Summary 11 "Runbook EntraSync" "OK" $rbName
        } catch { Write-StageFail $_.Exception.Message; Add-Summary 11 "Runbook EntraSync" "FAIL" $_.Exception.Message }
    } else { Add-Summary 11 "Runbook EntraSync" "SKIPPED" }
}

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 12: Schedule — Lifecycle (Daily)
# ──────────────────────────────────────────────────────────────────────────────
Write-Stage 12 "Schedule Lifecycle" "Create daily schedule for Lifecycle runbook"
if (Should-RunStage 12) {
    $proceed = Confirm-Stage 12
    if ($proceed -and -not $PlanOnly) {
        try {
            $schedName = "sched-mde-governance-lifecycle-daily"
            $startTime = (Get-Date).Date.AddDays(1).AddHours(6).ToString("o")
            az automation schedule create --resource-group $global:rgName --automation-account-name $global:aaName --name $schedName --frequency Day --interval 1 --start-time $startTime --time-zone "America/Sao_Paulo" --description "MDE Device Governance — Daily lifecycle classification" --output none 2>$null
            $jobLink = az automation job-schedule create --resource-group $global:rgName --automation-account-name $global:aaName --runbook-name "MDE-DeviceGovernance-Lifecycle" --schedule-name $schedName --output none 2>$null
            Write-StageOk "Daily schedule '$schedName' linked to Lifecycle runbook"
            Add-Summary 12 "Sched Lifecycle" "OK" $schedName
        } catch { Write-StageFail $_.Exception.Message; Add-Summary 12 "Sched Lifecycle" "FAIL" $_.Exception.Message }
    } else { Add-Summary 12 "Sched Lifecycle" "SKIPPED" }
}

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 13: Schedule — Entra Sync (Hourly)
# ──────────────────────────────────────────────────────────────────────────────
Write-Stage 13 "Schedule Entra Sync" "Create hourly schedule for Entra Sync runbook"
if (Should-RunStage 13) {
    $proceed = Confirm-Stage 13
    if ($proceed -and -not $PlanOnly) {
        try {
            $schedName = "sched-mde-governance-entrasync-hourly"
            $startTime = (Get-Date).AddMinutes(5).ToString("o")
            az automation schedule create --resource-group $global:rgName --automation-account-name $global:aaName --name $schedName --frequency Hour --interval 1 --start-time $startTime --description "MDE Device Governance — Hourly Entra group sync" --output none 2>$null
            az automation job-schedule create --resource-group $global:rgName --automation-account-name $global:aaName --runbook-name "MDE-DeviceGovernance-EntraSync" --schedule-name $schedName --output none 2>$null
            Write-StageOk "Hourly schedule '$schedName' linked to EntraSync runbook"
            Add-Summary 13 "Sched EntraSync" "OK" $schedName
        } catch { Write-StageFail $_.Exception.Message; Add-Summary 13 "Sched EntraSync" "FAIL" $_.Exception.Message }
    } else { Add-Summary 13 "Sched EntraSync" "SKIPPED" }
}

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 14: Azure Policy
# ──────────────────────────────────────────────────────────────────────────────
Write-Stage 14 "Azure Policy" "Deploy DeployIfNotExists policy for MDE registry device tag"
if (Should-RunStage 14) {
    $proceed = Confirm-Stage 14
    if ($proceed -and -not $PlanOnly) {
        try {
            $policyDefPath = Join-Path $projectRoot "04-Azure-Policy\policy-definition.json"
            if (-not (Test-Path $policyDefPath)) { throw "policy-definition.json not found: $policyDefPath" }

            $policyDef = Get-Content $policyDefPath -Raw
            $subId     = $global:targetSub.id
            $scope     = "/subscriptions/$subId"

            # Create policy definition
            $policyDefResult = az policy definition create --name $global:policyName --display-name "MDE Device Governance — Apply Device Tag via Registry" --description "Applies MDE device group tag via registry key. Managed by MDE-DeviceGovernance v3.0." --rules $policyDefPath --mode Indexed --output json | ConvertFrom-Json
            Write-StageOk "Policy definition created: $($policyDefResult.name)"

            # Assign at subscription scope
            $assignResult = az policy assignment create --policy $global:policyName --name "$global:policyName-assign" --display-name "MDE Device Tag Assignment" --scope $scope --output json | ConvertFrom-Json
            Write-StageOk "Policy assigned at subscription scope: $($assignResult.name)"
            Add-Summary 14 "Azure Policy" "OK" $global:policyName
        } catch { Write-StageFail $_.Exception.Message; Add-Summary 14 "Azure Policy" "FAIL" $_.Exception.Message }
    } else { Add-Summary 14 "Azure Policy" "SKIPPED" }
}

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 15: Azure Automation Variables
# ──────────────────────────────────────────────────────────────────────────────
Write-Stage 15 "AA Variables" "Store TenantId, AppId, AppSecret in Azure Automation Variables"
if (Should-RunStage 15) {
    $proceed = Confirm-Stage 15
    if ($proceed -and -not $PlanOnly) {
        try {
            if ($cfg.autenticacao.tenantId -like "<*>") {
                Write-StageWarn "Credentials still at placeholder — enter them now OR fill config.json"
                Write-Host "  TenantId: " -NoNewline; $tenantId = Read-Host
                Write-Host "  AppId:    " -NoNewline; $appId    = Read-Host
                Write-Host "  AppSecret (hidden): " -NoNewline; $appSecret = Read-Host -AsSecureString
                $appSecretPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($appSecret))
            } else {
                $tenantId     = $cfg.autenticacao.tenantId
                $appId        = $cfg.autenticacao.appId
                $appSecretPlain = $cfg.autenticacao.appSecret
            }

            $vars = @(
                @{Name=$cfg.azureAutomation.nomeVariavel_tenantId;   Val=$tenantId;      Encrypted=$false}
                @{Name=$cfg.azureAutomation.nomeVariavel_appId;       Val=$appId;         Encrypted=$false}
                @{Name=$cfg.azureAutomation.nomeVariavel_appSecret;   Val=$appSecretPlain; Encrypted=$true}
            )
            foreach ($v in $vars) {
                az automation variable create --resource-group $global:rgName --automation-account-name $global:aaName --name $v.Name --value $v.Val --encrypted $v.Encrypted --output none 2>$null
                az automation variable update --resource-group $global:rgName --automation-account-name $global:aaName --name $v.Name --value $v.Val --encrypted $v.Encrypted --output none 2>$null
                Write-StageOk "Variable stored: $($v.Name) (encrypted=$($v.Encrypted))"
            }
            Add-Summary 15 "AA Variables" "OK" "TenantId, AppId, AppSecret"
        } catch { Write-StageFail $_.Exception.Message; Add-Summary 15 "AA Variables" "FAIL" $_.Exception.Message }
    } else { Add-Summary 15 "AA Variables" "SKIPPED" }
}

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 16: MDE Device Groups Guide
# ──────────────────────────────────────────────────────────────────────────────
Write-Stage 16 "Device Groups Guide" "Generate per-subscription MDE Device Groups setup HTML guide"
if (Should-RunStage 16) {
    $proceed = Confirm-Stage 16
    if ($proceed -and -not $PlanOnly) {
        try {
            $guideDir = Join-Path $projectRoot "Relatorios"
            if (-not (Test-Path $guideDir)) { New-Item -ItemType Directory -Path $guideDir -Force | Out-Null }

            $subs = az account list --all --output json | ConvertFrom-Json | Where-Object { $_.state -eq "Enabled" }
            $excluded = $cfg.descoberta.excluirSubscriptions
            $inScopeSubs = $subs | Where-Object { $excluded -notcontains $_.id }

            $htmlRows = $inScopeSubs | ForEach-Object {
                $shortName = ($_.name -replace 'ME-MngEnvMCAP\d+-[^-]+-','') -replace '[^a-zA-Z0-9-]','-'
                if ($shortName.Length -gt 20) { $shortName = $shortName.Substring(0,20) }
                "<tr><td>$($_.name)</td><td><code>$($_.id)</code></td><td><strong>$shortName</strong></td><td><code>DeviceName contains 'azure' or (AzureSubscriptionId in ('$($_.id)'))</code></td></tr>"
            }

            $html = @"
<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>MDE Device Groups Setup Guide — MDE-DeviceGovernance v3.0</title>
<style>body{font-family:Segoe UI,sans-serif;margin:40px;background:#f5f5f5}
h1{color:#0078d4}table{border-collapse:collapse;width:100%}
th{background:#0078d4;color:#fff;padding:8px 12px;text-align:left}
td{padding:8px 12px;border-bottom:1px solid #ddd;background:#fff}
code{background:#eee;padding:2px 4px;border-radius:3px;font-size:.9em}</style></head>
<body><h1>MDE Device Groups Setup Guide</h1>
<p><strong>Project:</strong> MDE-DeviceGovernance v3.0.0 | <strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm')</p>
<p>Navigate to <a href="https://security.microsoft.com/mde-device-groups">security.microsoft.com &gt; Settings &gt; Endpoints &gt; Device groups</a> and create one group per row below:</p>
<table><tr><th>Subscription Name</th><th>Subscription ID</th><th>Tag Value (Group Name in MDE)</th><th>KQL Condition (device group rule)</th></tr>
$($htmlRows -join "`n")
</table>
<h2>Instructions</h2>
<ol>
<li>For each row: <strong>Add device group</strong> → Name = Tag Value → Rank = auto → Match devices by query (paste KQL Condition) → Automation level as desired.</li>
<li>After lifecycle engine runs, devices will appear in their group based on subscription tag.</li>
<li>EFEMERO / INATIVO_7D / INATIVO_40D / DUPLICADA_EXCLUIR groups: create manually with condition <code>Tag contains 'EFEMERO'</code> etc.</li>
</ol>
</body></html>
"@
            $guidePath = Join-Path $guideDir "MDE-DeviceGroups-SetupGuide-$(Get-Date -Format 'yyyyMMdd').html"
            $html | Out-File -FilePath $guidePath -Encoding UTF8
            Write-StageOk "Device Groups guide saved: $guidePath"
            Add-Summary 16 "Device Groups Guide" "OK" $guidePath
        } catch { Write-StageFail $_.Exception.Message; Add-Summary 16 "Device Groups Guide" "FAIL" $_.Exception.Message }
    } else { Add-Summary 16 "Device Groups Guide" "SKIPPED" }
}

# ──────────────────────────────────────────────────────────────────────────────
# FINAL SUMMARY
# ──────────────────────────────────────────────────────────────────────────────
$elapsed = (Get-Date) - $startTime
Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║   DEPLOYMENT SUMMARY                                             ║" -ForegroundColor Cyan
Write-Host "  ╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

foreach ($s in $summary) {
    $color = switch ($s.Status) { "OK" { "Green" } "SKIPPED" { "Gray" } default { "Red" } }
    $pad = $s.Stage.ToString("D2")
    Write-Host ("  [{0}] Stage {1} — {2,-22} {3}" -f $s.Status, $pad, $s.Name, $s.Detail) -ForegroundColor $color
}

$ok   = ($summary | Where-Object Status -eq "OK").Count
$fail = ($summary | Where-Object Status -like "*FAIL*").Count
$skip = ($summary | Where-Object Status -eq "SKIPPED").Count
Write-Host ""
Write-Host "  Total: $ok OK | $fail FAIL | $skip SKIPPED | Duration: $([math]::Round($elapsed.TotalMinutes,1))min" -ForegroundColor $(if($fail -gt 0){"Yellow"}else{"Green"})
Write-Host ""
if ($fail -gt 0) {
    Write-Host "  ATTENTION: $fail stage(s) failed. Re-run with -SkipStages for successful ones." -ForegroundColor Yellow
    Write-Host "  Example: .\Deploy-MDE-DeviceGovernance.ps1 -SkipStages '1,2,3,4,5,6,7'" -ForegroundColor Gray
}
Write-Host "  NEXT: Run .\07-Tests\Test-E2E.ps1 to validate all stages end-to-end." -ForegroundColor Cyan
Write-Host ""

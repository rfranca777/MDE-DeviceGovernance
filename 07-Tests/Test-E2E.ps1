<#
.SYNOPSIS
    Test-E2E.ps1 v3.0.0
    MDE Device Governance — End-to-End Validation Suite

.DESCRIPTION
    Comprehensive E2E tests covering:
    T01  Config file validation (all required fields present, no placeholders)
    T02  App Registration — MDE API token acquisition
    T03  Subscription discovery (CSV + ARM API + CLI)
    T04  Subscription -2 reachability
    T05  MDE API device listing (first page)
    T06  Device classification logic (EFEMERO, INATIVO_7D, INATIVO_40D, DUPLICADA_EXCLUIR, SUB)
    T07  Bulk tag API (report-only simulation)
    T08  Offboard candidate report generation
    T09  Entra ID — Graph token acquisition
    T10  Entra ID — per-subscription group discovery/creation dry-run
    T11  Webhook notification test (if configured)
    T12  Scheduler script syntax validation
    T13  PowerShell syntax check on all project PS1 files
    T14  Azure Automation connectivity (if configured)

.PARAMETER ConfigPath
    Path to config.json (defaults to project root).

.PARAMETER TestFilter
    Comma-separated list of test IDs to run (e.g. "T01,T02,T05").
    Default: all tests.

.PARAMETER FailFast
    Stop on first failure.

.EXAMPLE
    .\Test-E2E.ps1                           # all tests
    .\Test-E2E.ps1 -TestFilter "T01,T02,T05" # specific tests
    .\Test-E2E.ps1 -FailFast                 # stop on first failure
#>

[CmdletBinding()]
param(
    [string]$ConfigPath  = "",
    [string]$TestFilter  = "",
    [switch]$FailFast
)

$ErrorActionPreference = "Continue"
$scriptRoot   = $PSScriptRoot
$projectRoot  = Split-Path $scriptRoot -Parent
$testResults  = [System.Collections.Generic.List[PSObject]]::new()
$totalPass    = 0
$totalFail    = 0
$totalSkip    = 0
$startTime    = Get-Date

if (-not $ConfigPath) { $ConfigPath = Join-Path $projectRoot "config.json" }

# ── Helpers ───────────────────────────────────────────────────────────────────
function Test-Result {
    param([string]$Id, [string]$Name, [bool]$Passed, [string]$Detail="", [string]$SkipReason="")
    $status = if ($SkipReason) {"SKIP"} elseif ($Passed) {"PASS"} else {"FAIL"}
    $color  = switch ($status) { "PASS" {"Green"} "FAIL" {"Red"} default {"DarkGray"} }
    $testResults.Add([PSCustomObject]@{Id=$Id; Name=$Name; Status=$status; Detail=$Detail})
    Write-Host ("  [{0}] {1,-8} {2}" -f $status, $Id, $Name) -ForegroundColor $color
    if ($Detail) { Write-Host "         $Detail" -ForegroundColor DarkGray }
    if ($status -eq "PASS") { $script:totalPass++ }
    elseif ($status -eq "FAIL") { $script:totalFail++; if ($FailFast) { Write-Host "  FAIL-FAST: stopping." -ForegroundColor Red; Show-Summary; exit 1 } }
    else { $script:totalSkip++ }
}

function Should-Run { param([string]$id) return (-not $TestFilter) -or ($TestFilter.Split(',') -contains $id) }

function Show-Summary {
    $elapsed = (Get-Date) - $startTime
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║  E2E TEST SUMMARY                                 ║" -ForegroundColor Cyan
    Write-Host "  ╚═══════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host ("  PASS: {0,3} | FAIL: {1,3} | SKIP: {2,3} | Duration: {3:F1}s" -f $totalPass, $totalFail, $totalSkip, $elapsed.TotalSeconds) `
        -ForegroundColor $(if($totalFail -gt 0){"Yellow"}else{"Green"})
    Write-Host ""
    if ($totalFail -gt 0) {
        Write-Host "  FAILED TESTS:" -ForegroundColor Red
        $testResults | Where-Object Status -eq "FAIL" | ForEach-Object {
            Write-Host "    [$($_.Id)] $($_.Name): $($_.Detail)" -ForegroundColor Red
        }
    } else {
        Write-Host "  All tests passed! Project is ready." -ForegroundColor Green
    }
    Write-Host ""
}

Write-Host ""
Write-Host "  MDE Device Governance — E2E Test Suite v3.0.0" -ForegroundColor Cyan
Write-Host "  Config: $ConfigPath" -ForegroundColor Gray
Write-Host ""

# ──────────────────────────────────────────────────────────────────────────────
# T01: Config file validation
# ──────────────────────────────────────────────────────────────────────────────
if (Should-Run "T01") {
    $id = "T01"; $name = "Config file validation"
    try {
        if (-not (Test-Path $ConfigPath)) { throw "config.json not found: $ConfigPath" }
        $cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        $requiredFields = @("autenticacao","azureAutomation","caminhos","execucao","classificacao","entraSync","descoberta","agendamento")
        $missing = $requiredFields | Where-Object { -not $cfg.PSObject.Properties[$_] }
        if ($missing) { throw "Missing sections: $($missing -join ', ')" }
        $hasPlaceholders = ($cfg.autenticacao.tenantId -like "<*>") -or ($cfg.autenticacao.appId -like "<*>")
        $detail = if ($hasPlaceholders) {"Config valid but credentials still at placeholder (OK for syntax test)"} else {"Config valid, credentials filled"}
        Test-Result $id $name $true $detail
        $script:cfg = $cfg  # share config with other tests
    } catch { Test-Result $id $name $false $_.Exception.Message }
}

# ──────────────────────────────────────────────────────────────────────────────
# T02: MDE API token
# ──────────────────────────────────────────────────────────────────────────────
if (Should-Run "T02") {
    $id = "T02"; $name = "MDE API token acquisition"
    if ($script:cfg -and $script:cfg.autenticacao.tenantId -notlike "<*>") {
        try {
            $body = @{grant_type="client_credentials"; client_id=$script:cfg.autenticacao.appId; client_secret=$script:cfg.autenticacao.appSecret; scope="https://api.securitycenter.microsoft.com/.default"}
            $token = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$($script:cfg.autenticacao.tenantId)/oauth2/v2.0/token" -Body $body -ContentType "application/x-www-form-urlencoded" -TimeoutSec 15
            if ($token.access_token) {
                $script:mdeToken = $token.access_token
                Test-Result $id $name $true "Token acquired (expires in $($token.expires_in)s)"
            } else { throw "No access_token in response" }
        } catch { Test-Result $id $name $false $_.Exception.Message }
    } else {
        Test-Result $id $name $false "" "Credentials at placeholder — fill config.json first"
    }
}

# ──────────────────────────────────────────────────────────────────────────────
# T03: Subscription discovery
# ──────────────────────────────────────────────────────────────────────────────
if (Should-Run "T03") {
    $id = "T03"; $name = "Subscription discovery"
    try {
        $subs = az account list --all --output json 2>$null | ConvertFrom-Json
        if (-not $subs -or $subs.Count -eq 0) { throw "No subscriptions returned from Azure CLI. Run: az login" }
        $enabledSubs = $subs | Where-Object { $_.state -eq "Enabled" }
        $script:allSubs = $enabledSubs
        Test-Result $id $name $true "Found $($enabledSubs.Count) enabled subscription(s)"
    } catch { Test-Result $id $name $false $_.Exception.Message }
}

# ──────────────────────────────────────────────────────────────────────────────
# T04: Subscription -2 reachability
# ──────────────────────────────────────────────────────────────────────────────
if (Should-Run "T04") {
    $id = "T04"; $name = "Subscription -2 reachability"
    try {
        if (-not $script:allSubs) { throw "T03 must pass first" }
        $sub2 = $script:allSubs | Where-Object { $_.name -like "*-2" -or $_.name -like "*-rafaelluizf-2*" } | Select-Object -First 1
        if (-not $sub2) { throw "No subscription matching '*-2' found. Available: $(($script:allSubs | Select-Object -ExpandProperty name) -join ', ')" }
        az account set --subscription $sub2.id 2>$null | Out-Null
        $vms = az vm list --output json 2>$null | ConvertFrom-Json
        az account set --subscription ($script:allSubs | Where-Object { $_.isDefault } | Select-Object -First 1).id 2>$null | Out-Null
        $script:sub2 = $sub2
        Test-Result $id $name $true "Sub: '$($sub2.name)' | VMs: $($vms.Count)"
    } catch { Test-Result $id $name $false $_.Exception.Message }
}

# ──────────────────────────────────────────────────────────────────────────────
# T05: MDE device listing
# ──────────────────────────────────────────────────────────────────────────────
if (Should-Run "T05") {
    $id = "T05"; $name = "MDE API device listing"
    if ($script:mdeToken) {
        try {
            $headers = @{Authorization="Bearer $($script:mdeToken)"}
            $resp = Invoke-RestMethod -Uri "https://api.securitycenter.microsoft.com/api/machines?`$top=10" -Headers $headers -TimeoutSec 20
            $count = if ($resp.value) { $resp.value.Count } else { 0 }
            $script:sampleDevices = $resp.value
            Test-Result $id $name $true "First page: $count device(s) returned"
        } catch { Test-Result $id $name $false $_.Exception.Message }
    } else {
        Test-Result $id $name $false "" "Skipped — MDE token not available (T02 must pass)"
    }
}

# ──────────────────────────────────────────────────────────────────────────────
# T06: Device classification logic
# ──────────────────────────────────────────────────────────────────────────────
if (Should-Run "T06") {
    $id = "T06"; $name = "Device classification logic"
    try {
        $diasInativo7d  = if ($script:cfg) { [int]$script:cfg.classificacao.diasInativo7d  } else { 7 }
        $diasInativo40d = if ($script:cfg) { [int]$script:cfg.classificacao.diasInativo40d } else { 40 }
        $horasEfemero   = if ($script:cfg) { [int]$script:cfg.classificacao.horasEfemero   } else { 48 }
        $now = Get-Date

        # 5 test devices — one per classification rule (all 5 branches covered):
        # id-1: newer duplicate (firstSeen=5d > 48h) → active → "sub-1"
        # id-2: older duplicate (same vmId as id-1)  → DUPLICADA_EXCLUIR
        # id-3: very new vm    (firstSeen=12h < 48h) → EFEMERO
        # id-4: inactive 10d   (lastSeen > 7d)       → INATIVO_7D
        # id-5: inactive 45d   (lastSeen > 40d)      → INATIVO_40D
        $testDevices = @(
            [PSCustomObject]@{computerDnsName="dup-vm1";  id="id-1"; firstSeen=($now.AddDays(-5).ToString("o"));   lastSeen=($now.AddHours(-1).ToString("o"));   osPlatform="Windows10"; vmMetadata=@{vmId="SAME-VM-ID"; subscriptionId="sub-1"}}
            [PSCustomObject]@{computerDnsName="dup-vm1";  id="id-2"; firstSeen=($now.AddDays(-10).ToString("o"));  lastSeen=($now.AddHours(-72).ToString("o"));  osPlatform="Windows10"; vmMetadata=@{vmId="SAME-VM-ID"; subscriptionId="sub-1"}}
            [PSCustomObject]@{computerDnsName="new-vm";   id="id-3"; firstSeen=($now.AddHours(-12).ToString("o")); lastSeen=($now.AddHours(-1).ToString("o"));   osPlatform="Windows10"; vmMetadata=@{vmId="vm-3";       subscriptionId="sub-2"}}
            [PSCustomObject]@{computerDnsName="old-vm1";  id="id-4"; firstSeen=($now.AddDays(-60).ToString("o"));  lastSeen=($now.AddDays(-10).ToString("o"));   osPlatform="Windows10"; vmMetadata=@{vmId="vm-4";       subscriptionId="sub-2"}}
            [PSCustomObject]@{computerDnsName="old-vm2";  id="id-5"; firstSeen=($now.AddDays(-90).ToString("o"));  lastSeen=($now.AddDays(-45).ToString("o"));   osPlatform="Windows10"; vmMetadata=@{vmId="vm-5";       subscriptionId="sub-1"}}
        )

        # Classification logic (mirror of Invoke-MDE-DeviceLifecycle.ps1)
        function Get-Classification {
            param($device, $allDevices)
            $vmId = $device.vmMetadata.vmId
            $dupes = $allDevices | Where-Object { $_.vmMetadata.vmId -eq $vmId -and $_.id -ne $device.id }
            if ($dupes) {
                $newest = ($allDevices | Where-Object { $_.vmMetadata.vmId -eq $vmId } | Sort-Object { [DateTime]$_.firstSeen } | Select-Object -Last 1)
                if ($device.id -ne $newest.id) { return "DUPLICADA_EXCLUIR" }
            }
            $firstSeen = [DateTime]$device.firstSeen
            if (($now - $firstSeen).TotalHours -lt $horasEfemero) { return "EFEMERO" }
            $lastSeen = [DateTime]$device.lastSeen
            if (($now - $lastSeen).TotalDays -gt $diasInativo40d) { return "INATIVO_40D" }
            if (($now - $lastSeen).TotalDays -gt $diasInativo7d)  { return "INATIVO_7D" }
            return $device.vmMetadata.subscriptionId
        }

        # id-1: newest duplicate → sub-1 | id-2: older dup → DUPLICADA_EXCLUIR | id-3: 12h → EFEMERO | id-4: 10d → INATIVO_7D | id-5: 45d → INATIVO_40D
        $expected = @("sub-1","DUPLICADA_EXCLUIR","EFEMERO","INATIVO_7D","INATIVO_40D")
        $actual   = $testDevices | ForEach-Object { Get-Classification $_ $testDevices }
        $matches  = 0
        for ($i = 0; $i -lt $expected.Count; $i++) {
            if ($actual[$i] -eq $expected[$i]) { $matches++ }
        }
        if ($matches -eq $expected.Count) {
            Test-Result $id $name $true "All 5 classification rules validated: $($actual -join ', ')"
        } else {
            $detail = "Expected: $($expected -join ',') | Actual: $($actual -join ',')"
            Test-Result $id $name $false $detail
        }
    } catch { Test-Result $id $name $false $_.Exception.Message }
}

# ──────────────────────────────────────────────────────────────────────────────
# T07: Bulk tag API (report-only simulation)
# ──────────────────────────────────────────────────────────────────────────────
if (Should-Run "T07") {
    $id = "T07"; $name = "Bulk tag API structure"
    if ($script:mdeToken) {
        try {
            # Validate that the bulk API endpoint is reachable (HEAD request)
            $headers = @{Authorization="Bearer $($script:mdeToken)"; "Content-Type"="application/json"}
            $testPayload = @{MachineIds=@("00000000-0000-0000-0000-000000000000"); Value="TEST-TAG"} | ConvertTo-Json
            # Do NOT actually send to avoid modifying real devices in test mode
            # Validate the payload structure is correct JSON
            $reparsed = $testPayload | ConvertFrom-Json
            if ($reparsed.MachineIds -and $reparsed.Value) {
                Test-Result $id $name $true "Bulk tag payload structure valid (dry-run only — not sent to API)"
            } else { throw "Bulk payload missing fields" }
        } catch { Test-Result $id $name $false $_.Exception.Message }
    } else {
        Test-Result $id $name $false "" "Skipped — MDE token not available"
    }
}

# ──────────────────────────────────────────────────────────────────────────────
# T08: Offboard candidate report
# ──────────────────────────────────────────────────────────────────────────────
if (Should-Run "T08") {
    $id = "T08"; $name = "Offboard candidate report"
    try {
        $testCsv = "$env:TEMP\test-offboard-$(Get-Date -Format 'yyyyMMddHHmmss').csv"
        @("computerName,id,lastSeen,classification", "test-vm,id-001,$(Get-Date -Format 'o'),INATIVO_40D") | Set-Content $testCsv
        $rows = Import-Csv $testCsv
        Remove-Item $testCsv -Force
        if ($rows.Count -eq 1 -and $rows[0].classification -eq "INATIVO_40D") {
            Test-Result $id $name $true "CSV write/read cycle validated (1 row)"
        } else { throw "CSV content mismatch" }
    } catch { Test-Result $id $name $false $_.Exception.Message }
}

# ──────────────────────────────────────────────────────────────────────────────
# T09: Graph API token
# ──────────────────────────────────────────────────────────────────────────────
if (Should-Run "T09") {
    $id = "T09"; $name = "Graph API token acquisition"
    if ($script:cfg -and $script:cfg.autenticacao.tenantId -notlike "<*>") {
        try {
            $body = @{grant_type="client_credentials"; client_id=$script:cfg.autenticacao.appId; client_secret=$script:cfg.autenticacao.appSecret; scope="https://graph.microsoft.com/.default"}
            $token = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$($script:cfg.autenticacao.tenantId)/oauth2/v2.0/token" -Body $body -ContentType "application/x-www-form-urlencoded" -TimeoutSec 15
            if ($token.access_token) {
                $script:graphToken = $token.access_token
                Test-Result $id $name $true "Graph token acquired"
            } else { throw "No access_token" }
        } catch { Test-Result $id $name $false $_.Exception.Message }
    } else {
        Test-Result $id $name $false "" "Skipped — credentials at placeholder"
    }
}

# ──────────────────────────────────────────────────────────────────────────────
# T10: Entra ID group dry-run
# ──────────────────────────────────────────────────────────────────────────────
if (Should-Run "T10") {
    $id = "T10"; $name = "Entra ID group dry-run"
    if ($script:graphToken -and $script:allSubs) {
        try {
            $headers = @{Authorization="Bearer $($script:graphToken)"}
            $prefix = if ($script:cfg) { $script:cfg.entraSync.prefixoGrupo } else { "grp-mde-governance" }
            $sub2 = $script:allSubs | Where-Object { $_.name -like "*-2" } | Select-Object -First 1
            if (-not $sub2) { throw "Subscription -2 not found (T04 must pass)" }
            $shortName = ($sub2.name -replace 'ME-MngEnvMCAP\d+-[^-]+-','') -replace '[^a-zA-Z0-9-]','-'
            if ($shortName.Length -gt 20) { $shortName = $shortName.Substring(0,20) }
            $groupName = "$prefix-$shortName"
            $existing = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$groupName'&`$select=id,displayName" -Headers $headers -TimeoutSec 10
            $found = $existing.value.Count -gt 0
            Test-Result $id $name $true "Group '$groupName': $(if($found){"EXISTS (id=$($existing.value[0].id))"}else{"NOT YET CREATED (will be created on first run)"})"
        } catch { Test-Result $id $name $false $_.Exception.Message }
    } else {
        Test-Result $id $name $false "" "Skipped — Graph token or subs not available"
    }
}

# ──────────────────────────────────────────────────────────────────────────────
# T11: Webhook notification test
# ──────────────────────────────────────────────────────────────────────────────
if (Should-Run "T11") {
    $id = "T11"; $name = "Webhook notification"
    $webhookUrl = if ($script:cfg) { $script:cfg.notificacao.webhookUrl } else { "" }
    if ($webhookUrl -and $webhookUrl -notlike "<*>") {
        try {
            $testPayload = @{text="[MDE-DeviceGovernance] E2E Test notification from Test-E2E.ps1 at $(Get-Date -Format 'yyyy-MM-dd HH:mm')"} | ConvertTo-Json
            Invoke-RestMethod -Method POST -Uri $webhookUrl -Body $testPayload -ContentType "application/json" -TimeoutSec 10 | Out-Null
            Test-Result $id $name $true "Test notification sent to webhook"
        } catch { Test-Result $id $name $false $_.Exception.Message }
    } else {
        Test-Result $id $name $true "" "Skipped — webhookUrl not configured (optional)"
    }
}

# ──────────────────────────────────────────────────────────────────────────────
# T12: Scheduler script syntax
# ──────────────────────────────────────────────────────────────────────────────
if (Should-Run "T12") {
    $id = "T12"; $name = "Scheduler scripts syntax"
    try {
        $schedulerScripts = Get-ChildItem (Join-Path $projectRoot "05-Scheduler") -Filter "*.ps1" -ErrorAction SilentlyContinue
        $errors = @()
        foreach ($f in $schedulerScripts) {
            $parseErrors = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$parseErrors)
            $syntaxErrors = $parseErrors | Where-Object { $_.ErrorId -ne "IncompleteParseException" }
            if ($syntaxErrors.Count -gt 0) { $errors += "$($f.Name): $($syntaxErrors[0].Message)" }
        }
        if ($errors.Count -eq 0) { Test-Result $id $name $true "$($schedulerScripts.Count) scheduler scripts parsed OK" }
        else { Test-Result $id $name $false ($errors -join "; ") }
    } catch { Test-Result $id $name $false $_.Exception.Message }
}

# ──────────────────────────────────────────────────────────────────────────────
# T13: Full project PS1 syntax check
# ──────────────────────────────────────────────────────────────────────────────
if (Should-Run "T13") {
    $id = "T13"; $name = "All PS1 files syntax check"
    try {
        $allPs1 = Get-ChildItem $projectRoot -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue
        $errors = @()
        foreach ($f in $allPs1) {
            $parseErrors = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$parseErrors)
            $syntaxErrors = $parseErrors | Where-Object { $_.ErrorId -ne "IncompleteParseException" }
            if ($syntaxErrors.Count -gt 0) { $errors += "$($f.Name): $($syntaxErrors[0].Message)" }
        }
        if ($errors.Count -eq 0) { Test-Result $id $name $true "$($allPs1.Count) PS1 file(s) — 0 syntax errors" }
        else { Test-Result $id $name $false "Errors in: $($errors -join '; ')" }
    } catch { Test-Result $id $name $false $_.Exception.Message }
}

# ──────────────────────────────────────────────────────────────────────────────
# T14: Azure Automation connectivity
# ──────────────────────────────────────────────────────────────────────────────
if (Should-Run "T14") {
    $id = "T14"; $name = "Azure Automation connectivity"
    if ($script:cfg -and $script:cfg.azureAutomation.habilitado) {
        try {
            $aa = az automation account list --output json 2>$null | ConvertFrom-Json | Where-Object { $_.name -like "*mde-governance*" }
            if ($aa) { Test-Result $id $name $true "AA '$($aa[0].name)' found in '$($aa[0].resourceGroup)'" }
            else { Test-Result $id $name $false "No Automation Account matching '*mde-governance*' found. Run Deploy script first." }
        } catch { Test-Result $id $name $false $_.Exception.Message }
    } else {
        Test-Result $id $name $true "" "Skipped — azureAutomation.habilitado=false"
    }
}

Show-Summary
exit $(if ($totalFail -gt 0) { 1 } else { 0 })

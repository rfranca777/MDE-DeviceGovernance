<#
.SYNOPSIS
    Run-Governance.ps1 v2.0.0
    MDE Device Governance — Periodic Execution Wrapper

.DESCRIPTION
    Orchestrates the complete MDE Device Governance pipeline:
    1. Loads config.json
    2. Validates prerequisites
    3. Executes lifecycle classification (Invoke-MDE-DeviceLifecycle.ps1)
    4. Optionally executes Entra Group Sync (Invoke-EntraGroupSync.ps1)
    5. Organizes logs and reports
    6. Log rotation (removes files older than logRetentionDays)
    7. Audit record
    8. Email/webhook notification

    v2.0 improvements:
    ✔ Passes ALL configurable thresholds to lifecycle engine (was missing in v1.0)
    ✔ Entra Group Sync integrated
    ✔ Azure Automation and Managed Identity support
    ✔ Offboard candidate report generation

.NOTES
    Version: 2.0.0 | 2026-03-02
    Called by: Scheduled Task or manual execution
    DO NOT EDIT — customize via config.json
#>

param (
    [Parameter(Mandatory=$false)] [switch]$Force,
    [Parameter(Mandatory=$false)] [switch]$ReportOnly,
    [Parameter(Mandatory=$false)] [switch]$SkipEntraSync
)

$ErrorActionPreference = "Continue"
$scriptRoot    = $PSScriptRoot
$configPath    = Join-Path $scriptRoot "config.json"
$runTimestamp  = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$exitCode      = 0

function Show-Banner {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║   MDE Device Governance — Run-Governance.ps1 v2.0.0        ║" -ForegroundColor Cyan
    Write-Host "  ║   $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')                                         ║" -ForegroundColor White
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-RunLog {
    param ([string]$Msg, [string]$Level = "INFO")
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts [$Level] $Msg"
    Add-Content -Path $runLogPath -Value $line -ErrorAction SilentlyContinue
    switch ($Level) {
        "INFO"  { Write-Host "  [INFO]  $Msg" -ForegroundColor Cyan }
        "WARN"  { Write-Host "  [WARN]  $Msg" -ForegroundColor Yellow }
        "ERROR" { Write-Host "  [ERROR] $Msg" -ForegroundColor Red }
        "OK"    { Write-Host "  [OK]    $Msg" -ForegroundColor Green }
    }
}

Show-Banner

# ── Load config ──────────────────────────────────────────────────────────────
Write-Host "  Carregando config.json..." -ForegroundColor DarkCyan
if (-not (Test-Path $configPath)) {
    Write-Host "  ERROR: config.json not found at: $configPath" -ForegroundColor Red
    exit 1
}
try {
    $config = Get-Content $configPath -Raw | ConvertFrom-Json
    Write-Host "  Configuration loaded." -ForegroundColor Green
}
catch {
    Write-Host "  ERROR reading config.json: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ── Validate mandatory fields ─────────────────────────────────────────────────
$aaEnabled = $config.azureAutomation.habilitado
$miEnabled = $config.azureAutomation.usarManagedIdentity

if (-not $aaEnabled) {
    $required = @(
        @{ Path = "autenticacao.tenantId";  Value = $config.autenticacao.tenantId  },
        @{ Path = "autenticacao.appId";     Value = $config.autenticacao.appId     },
        @{ Path = "autenticacao.appSecret"; Value = $config.autenticacao.appSecret }
    )
    $valid = $true
    foreach ($f in $required) {
        if ([string]::IsNullOrWhiteSpace($f.Value) -or $f.Value -like "<*>") {
            Write-Host "  ERROR: Missing required config field: $($f.Path)" -ForegroundColor Red
            $valid = $false
        }
    }
    if (-not $valid) {
        Write-Host "  Fill in credentials in config.json or set azureAutomation.habilitado=true" -ForegroundColor Yellow
        exit 1
    }
}

# ── Prepare directories ───────────────────────────────────────────────────────
$logsDir    = Join-Path $scriptRoot ($config.caminhos.pastaLogs     -replace '^\.\\'  , '')
$reportsDir = Join-Path $scriptRoot ($config.caminhos.pastaRelatorios -replace '^\.\\'  , '')
$runLogPath = Join-Path $logsDir "Run-Governance-$runTimestamp.log"

foreach ($dir in @($logsDir, $reportsDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

Write-RunLog "=== GOVERNANCE RUN START ==="
Write-RunLog "Version: 2.0.0 | Host: $env:COMPUTERNAME | User: $env:USERNAME"
Write-RunLog "Config: $configPath"

# ── Determine execution mode ──────────────────────────────────────────────────
$isReportOnly = [bool]$config.execucao.reportOnly
if ($ReportOnly.IsPresent) { $isReportOnly = $true }

if (-not $isReportOnly -and $config.seguranca.confirmarExecucaoReal -and -not $Force.IsPresent) {
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "  ║  WARNING: LIVE MODE — Tags WILL be applied!               ║" -ForegroundColor Yellow
    Write-Host "  ╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Confirm LIVE execution? (S/N): " -ForegroundColor Yellow -NoNewline
    $confirm = Read-Host
    if ($confirm -notmatch '^[Ss]') {
        Write-RunLog "Execution cancelled by user." -Level WARN
        exit 0
    }
}

$modeText  = if ($isReportOnly) { "REPORT-ONLY (no changes)" } else { "LIVE (tags will be applied)" }
Write-Host ""
Write-Host "  Mode: $modeText" -ForegroundColor $(if($isReportOnly){"Green"}else{"Yellow"})
Write-RunLog "Mode: $modeText"

# ── Display active configuration ──────────────────────────────────────────────
$threshInativo7d  = [int]($config.classificacao.diasInativo7d  ?? 7)
$threshInativo40d = [int]($config.classificacao.diasInativo40d ?? 40)
$threshEfemero    = [int]($config.classificacao.horasEfemero   ?? 48)
$autoDiscover     = [bool]($config.descoberta.autoDiscoverSubscriptions ?? $true)
$saveCsv          = [bool]($config.descoberta.salvarCsvAposDiscovery ?? $true)
$excludeSubs      = @($config.descoberta.excluirSubscriptions ?? @())
$csvPath          = Join-Path $scriptRoot ($config.caminhos.subscriptionMappingCsv -replace '^\.\\','')
$mainScript       = Join-Path $scriptRoot ($config.caminhos.scriptLifecycle -replace '^\.\\','')
$entraScript      = Join-Path $scriptRoot ($config.caminhos.scriptEntraSync -replace '^\.\\','')
$offboardCsv      = if ($config.caminhos.offboardCandidatesCsv) {
                        (Join-Path $reportsDir "offboard-candidates-$(Get-Date -f yyyyMMdd).csv")
                    } else { "" }
$webhookUrl       = $config.notificacao.webhookUrl ?? ""

Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
Write-Host "  │ ACTIVE CONFIGURATION                                         │" -ForegroundColor White
Write-Host "  │  Thresholds: INATIVO_7D=${threshInativo7d}d | INATIVO_40D=${threshInativo40d}d | EFEMERO=${threshEfemero}h $((' ').PadRight(14))│" -ForegroundColor Cyan
Write-Host "  │  Discovery:  $(if($autoDiscover){'Auto (ARM→CLI→MDE-metadata)'}else{'Manual CSV'})$((' ').PadRight(34))│" -ForegroundColor $(if($autoDiscover){"Green"}else{"Gray"})
Write-Host "  │  AA Mode:    $(if($aaEnabled){'Azure Automation Variables'}else{'Config file credentials'})$((' ').PadRight(34))│" -ForegroundColor $(if($aaEnabled){"Green"}else{"Gray"})
Write-Host "  │  MI Token:   $(if($miEnabled){'Managed Identity (zero secrets for ARM)'}else{'Client credentials'})$((' ').PadRight(23))│" -ForegroundColor $(if($miEnabled){"Green"}else{"Gray"})
Write-Host "  │  EntraSync:  $(if(!$SkipEntraSync -and $config.entraSync.habilitado){'Enabled'}else{'Disabled'})$((' ').PadRight(51))│" -ForegroundColor $(if(!$SkipEntraSync -and $config.entraSync.habilitado){"Green"}else{"Gray"})
Write-Host "  └──────────────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
Write-Host ""

# ── Execute Lifecycle Engine ──────────────────────────────────────────────────
Write-RunLog "── Executing lifecycle engine ──"
Write-Host "  Executing Invoke-MDE-DeviceLifecycle.ps1..." -ForegroundColor DarkCyan

if (-not (Test-Path $mainScript)) {
    Write-RunLog "Lifecycle script not found: $mainScript" -Level ERROR; exit 1
}

$startTime = Get-Date
$lifecycleDir = Split-Path $mainScript -Parent
Push-Location $lifecycleDir

try {
    $params = @{
        subscriptionMappingPath   = $csvPath
        autoDiscoverSubscriptions = $autoDiscover
        saveDiscoveredCsv         = $saveCsv
        excludeSubscriptions      = $excludeSubs
        reportOnly                = $isReportOnly
        diasInativo7d             = $threshInativo7d
        diasInativo40d            = $threshInativo40d
        horasEfemero              = $threshEfemero
        UseAzureAutomation        = $aaEnabled
        UseManagedIdentity        = $miEnabled
    }

    if (-not $aaEnabled) {
        $params.tenantId  = $config.autenticacao.tenantId
        $params.appId     = $config.autenticacao.appId
        $params.appSecret = $config.autenticacao.appSecret
    }

    if ($offboardCsv) { $params.OffboardCandidateReportPath = $offboardCsv }
    if ($webhookUrl)  { $params.NotifyWebhookUrl = $webhookUrl }

    & $mainScript @params
    $lifecycleExitCode = $LASTEXITCODE ?? 0
    $duration = (Get-Date) - $startTime
    Write-RunLog "Lifecycle engine finished in $([math]::Round($duration.TotalSeconds,1))s (exit: $lifecycleExitCode)" -Level OK
}
catch {
    $lifecycleExitCode = 1
    $duration = (Get-Date) - $startTime
    Write-RunLog "Lifecycle engine ERROR: $($_.Exception.Message)" -Level ERROR
    $exitCode = 1
}
finally { Pop-Location }

# ── Move lifecycle artifacts to organized folders ─────────────────────────────
$moved = 0
Get-ChildItem (Split-Path $mainScript -Parent) -Filter "DeviceLifecycle-Report-*.csv" -ErrorAction SilentlyContinue | ForEach-Object {
    Move-Item $_.FullName -Destination $reportsDir -Force
    Write-RunLog "Report moved: $($_.Name)" -Level OK; $moved++
}
Get-ChildItem (Split-Path $mainScript -Parent) -Filter "DeviceLifecycle-Log-*.log" -ErrorAction SilentlyContinue | ForEach-Object {
    Move-Item $_.FullName -Destination $logsDir -Force; $moved++
}
if ($moved -gt 0) { Write-Host "  $moved artifact(s) organized." -ForegroundColor Green }

# ── Execute Entra Group Sync (optional) ──────────────────────────────────────
if (-not $SkipEntraSync -and $config.entraSync.habilitado -and (Test-Path $entraScript)) {
    Write-Host ""
    Write-Host "  Executing Invoke-EntraGroupSync.ps1..." -ForegroundColor DarkCyan
    Write-RunLog "── Executing Entra Group Sync ──"

    $entraStart = Get-Date
    try {
        $entraParams = @{
            prefixoGrupo       = $config.entraSync.prefixoGrupo       ?? "grp-mde-governance"
            incluirArc         = [bool]($config.entraSync.incluirArc ?? $true)
            removerMembrosSemVm= [bool]($config.entraSync.removerMembrosSemVm ?? $true)
            reportOnly         = $isReportOnly
            UseAzureAutomation = $aaEnabled
            UseManagedIdentity = $miEnabled
            excludeSubscriptions = $excludeSubs
        }
        if (-not $aaEnabled) {
            $entraParams.tenantId  = $config.autenticacao.tenantId
            $entraParams.appId     = $config.autenticacao.appId
            $entraParams.appSecret = $config.autenticacao.appSecret
        }

        & $entraScript @entraParams
        Write-RunLog "Entra Group Sync finished in $([math]::Round(((Get-Date)-$entraStart).TotalSeconds,1))s" -Level OK
    }
    catch {
        Write-RunLog "Entra Group Sync ERROR (non-critical): $($_.Exception.Message)" -Level WARN
    }

    # Move Entra sync logs
    Get-ChildItem (Split-Path $entraScript -Parent) -Filter "EntraSync-Log-*.log" -ErrorAction SilentlyContinue | ForEach-Object {
        Move-Item $_.FullName -Destination $logsDir -Force
    }
}

# ── Log rotation ──────────────────────────────────────────────────────────────
$retentionDays = [int]($config.execucao.logRetentionDays ?? 30)
$cutoff        = (Get-Date).AddDays(-$retentionDays)
$cleaned       = 0
foreach ($dir in @($logsDir, $reportsDir)) {
    Get-ChildItem $dir -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt $cutoff } |
        ForEach-Object { Remove-Item $_.FullName -Force; $cleaned++ }
}
if ($cleaned -gt 0) {
    Write-RunLog "$cleaned old file(s) removed (retention: $retentionDays days)" -Level INFO
}

# ── Audit record ──────────────────────────────────────────────────────────────
if ($config.seguranca.auditarAlteracoes) {
    $auditPath = Join-Path $logsDir "AUDIT-$runTimestamp.txt"
    @"
═══════════════════════════════════════════════════
MDE Device Governance — Audit Record
═══════════════════════════════════════════════════
Timestamp:       $runTimestamp
Host:            $env:COMPUTERNAME
User:            $env:USERNAME
Mode:            $modeText
Thresholds:      INATIVO_7D=${threshInativo7d}d | INATIVO_40D=${threshInativo40d}d | EFEMERO=${threshEfemero}h
Discovery:       $(if ($autoDiscover) {'Auto-discovery'} else {'Manual CSV'})
AAMode:          $aaEnabled | MI: $miEnabled
EntraSync:       $($config.entraSync.habilitado)
ExcludedSubs:    $($excludeSubs -join ', ')
ExitCode:        $exitCode
═══════════════════════════════════════════════════
"@ | Set-Content $auditPath -Encoding UTF8
    Write-RunLog "Audit record saved: $auditPath"
}

# ── Email notification (optional) ─────────────────────────────────────────────
if ($config.notificacao.habilitado -and $config.notificacao.smtpServer) {
    try {
        $subject = "MDE DeviceGovernance — $(Get-Date -f 'dd/MM/yyyy') — $(if($exitCode -eq 0){'OK'}else{'ERROR'})"
        $body    = "<html><body><h2>MDE Device Governance Run</h2><p>Mode: $modeText</p><p>Date: $(Get-Date -f 'dd/MM/yyyy HH:mm')</p><p>Status: $(if($exitCode -eq 0){'SUCCESS'}else{'ERROR'})</p></body></html>"
        Send-MailMessage -From $config.notificacao.remetente -To $config.notificacao.destinatarios `
            -Subject $subject -Body $body -BodyAsHtml `
            -SmtpServer $config.notificacao.smtpServer -Port $config.notificacao.smtpPort -UseSsl:$config.notificacao.smtpUseSsl
        Write-RunLog "Email sent to: $($config.notificacao.destinatarios -join ', ')" -Level OK
    }
    catch { Write-RunLog "Email failed: $($_.Exception.Message)" -Level WARN }
}

# ── Final summary ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor $(if($exitCode -eq 0){"Green"}else{"Red"})
Write-Host "  ║  RUN $(if($exitCode -eq 0){'COMPLETED'.PadRight(53)}else{'FAILED'.PadRight(53)})║" -ForegroundColor $(if($exitCode -eq 0){"Green"}else{"Red"})
Write-Host "  ║  Total time: $([math]::Round(((Get-Date)-$startTime).TotalSeconds,1))s$((' ').PadRight(45))║" -ForegroundColor White
Write-Host "  ║  Logs:    $logsDir" -ForegroundColor Gray
Write-Host "  ║  Reports: $reportsDir" -ForegroundColor Gray
Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor $(if($exitCode -eq 0){"Green"}else{"Red"})
Write-Host ""

Write-RunLog "=== GOVERNANCE RUN END (exit: $exitCode) ==="
exit $exitCode

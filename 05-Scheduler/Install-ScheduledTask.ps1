<#
.SYNOPSIS
    Install-ScheduledTask.ps1 v2.0.0
    MDE Device Governance — Windows Task Scheduler Setup

.DESCRIPTION
    Creates a Windows Scheduled Task that runs Run-Governance.ps1 automatically.
    - Runs as SYSTEM account (no login required)
    - Schedule configured via config.json (horarioExecucao, intervaloHoras)
    - Includes event log integration for execution history
    - Idempotent: replaces existing task if present (with confirmation)

    REQUIRES: Administrator execution.
#>

$ErrorActionPreference = "Stop"
$scriptRoot = $PSScriptRoot

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║   MDE Device Governance — Scheduled Task Installer v2.0    ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Verify admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "  ERROR: Run this script as Administrator." -ForegroundColor Red
    exit 1
}

# Load config from project root (one level up from 05-Scheduler)
$configPath = Join-Path (Split-Path $scriptRoot -Parent) "config.json"
if (-not (Test-Path $configPath)) {
    Write-Host "  ERROR: config.json not found at: $configPath" -ForegroundColor Red
    exit 1
}

$config = Get-Content $configPath -Raw | ConvertFrom-Json

$taskName     = $config.agendamento.nomeTask         ?? "MDE-DeviceGovernance-Daily"
$taskDesc     = $config.agendamento.descricaoTask    ?? "MDE Device Governance daily lifecycle run"
$scheduleTime = $config.agendamento.horarioExecucao  ?? "06:00"
$intervalHrs  = [int]($config.agendamento.intervaloHoras ?? 24)
$runScript    = Join-Path (Split-Path $scriptRoot -Parent) "05-Scheduler\Run-Governance.ps1"

if (-not (Test-Path $runScript)) {
    Write-Host "  ERROR: Run-Governance.ps1 not found at: $runScript" -ForegroundColor Red
    exit 1
}

Write-Host "  ┌──────────────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
Write-Host "  │  SCHEDULED TASK TO CREATE                                    │" -ForegroundColor White
Write-Host "  │  Name:      $taskName" -ForegroundColor Cyan
Write-Host "  │  Schedule:  Daily at $scheduleTime (every ${intervalHrs}h)" -ForegroundColor Cyan
Write-Host "  │  Script:    $runScript" -ForegroundColor Gray
Write-Host "  │  Account:   SYSTEM (no login required)" -ForegroundColor Gray
Write-Host "  │  Mode:      $(if([bool]$config.execucao.reportOnly){'REPORT-ONLY (safe)'}else{'LIVE (applies tags)'})" -ForegroundColor $(if([bool]$config.execucao.reportOnly){"Green"}else{"Yellow"})
Write-Host "  └──────────────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
Write-Host ""

# Check if task already exists
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "  WARNING: Task '$taskName' already exists." -ForegroundColor Yellow
    Write-Host "  Replace? (S/N): " -ForegroundColor Yellow -NoNewline
    $resp = Read-Host
    if ($resp -notmatch '^[Ss]') { Write-Host "  Installation cancelled." -ForegroundColor Gray; exit 0 }
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host "  Existing task removed." -ForegroundColor Gray
}

# Build schedule trigger
$hh = [int]($scheduleTime.Split(':')[0])
$mm = [int]($scheduleTime.Split(':')[1])
$startAt = (Get-Date).Date.AddHours($hh).AddMinutes($mm)
if ($startAt -lt (Get-Date)) { $startAt = $startAt.AddDays(1) }

$trigger = if ($intervalHrs -ge 24) {
    New-ScheduledTaskTrigger -Daily -At $startAt
} else {
    # Repetition every N hours
    $trigger      = New-ScheduledTaskTrigger -Once -At $startAt
    $trigger.Repetition.Interval = "PT${intervalHrs}H"
    $trigger.Repetition.Duration = "P9999D"
    $trigger
}

$action   = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-NonInteractive -NoProfile -ExecutionPolicy Bypass -File `"$runScript`""
$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
    -RestartCount 2 `
    -RestartInterval (New-TimeSpan -Minutes 5) `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

try {
    Register-ScheduledTask -TaskName $taskName -Description $taskDesc `
        -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
    Write-Host "  Scheduled Task '$taskName' created successfully." -ForegroundColor Green
    Write-Host ""
    Write-Host "  Manage via: taskschd.msc" -ForegroundColor Gray
    Write-Host "  Run now:    Start-ScheduledTask -TaskName '$taskName'" -ForegroundColor Gray
    Write-Host "  Status:     Get-ScheduledTaskInfo -TaskName '$taskName'" -ForegroundColor Gray
    Write-Host "  Remove:     Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false" -ForegroundColor Gray
}
catch {
    Write-Host "  ERROR creating Scheduled Task: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

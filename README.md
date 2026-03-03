# MDE Device Governance v3.0.0

> **Unified lifecycle engine + Entra ID sync for Microsoft Defender for Endpoint devices at enterprise scale.**

[![Version](https://img.shields.io/badge/version-3.0.0-blue)](CHANGELOG.md)
[![PowerShell](https://img.shields.io/badge/PowerShell-7%2B-blue)](https://github.com/PowerShell/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Azure Automation](https://img.shields.io/badge/Azure-Automation-0078d4)](https://azure.microsoft.com/en-us/products/automation)

---

## Overview

**MDE-DeviceGovernance** combines two previously separate solutions into a single, production-grade governance framework:

| Capability | Source | v3.0 Enhancement |
|---|---|---|
| Device lifecycle classification | MDE-ServerTags v2.2 | Configurable thresholds, AA Variables, MI auth, offboard report, webhook |
| Entra ID group sync | MDE-PolicyAutomation v1.0.4 | Per-subscription groups, stale member removal, Arc support |
| Azure infrastructure deployment | MDE-PolicyAutomation v1.0.4 | 16 stages vs 14 (adds AA Variables + lifecycle runbook) |
| Azure Policy (registry tag) | MDE-PolicyAutomation v1.0.4 | Preserved + documentation improved |
| Windows Scheduled Task | MDE-ServerTags (Run-Daily.ps1) | Full config passthrough, Entra sync integrated |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     MDE Device Governance v3.0.0                           │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                     EXECUTION LAYER                                 │   │
│  │                                                                     │   │
│  │  Option A: Windows Task Scheduler (on-prem / hybrid)               │   │
│  │    05-Scheduler/Run-Governance.ps1  (daily @ 06:00)                │   │
│  │         │                                                           │   │
│  │  Option B: Azure Automation (cloud-native)                         │   │
│  │    06-Runbooks/Runbook-Lifecycle.ps1   (daily)                     │   │
│  │    06-Runbooks/Runbook-EntraSync.ps1   (hourly)                    │   │
│  └──────────────────────────┬──────────────────────────────────────────┘   │
│                             │                                               │
│             ┌───────────────┼───────────────┐                              │
│             ▼               ▼               ▼                              │
│  ┌──────────────────┐ ┌──────────────┐ ┌──────────────────────────────┐   │
│  │   LIFECYCLE      │ │  ENTRA SYNC  │ │     AZURE INFRASTRUCTURE     │   │
│  │  ENGINE v3.0     │ │  v2.0        │ │                              │   │
│  │                  │ │              │ │  Automation Account          │   │
│  │  4-level sub     │ │  Per-sub     │ │  Managed Identity            │   │
│  │  discovery       │ │  Entra ID    │ │  RBAC Reader (all subs)      │   │
│  │                  │ │  Security    │ │  Azure Policy (DINE/AuditIfNE│   │
│  │  5-priority      │ │  Groups      │ │  AA Variables (encrypted)    │   │
│  │  classification: │ │              │ │  Runbooks + Schedules        │   │
│  │  DUPLICADA       │ │  Stale       │ └──────────────────────────────┘   │
│  │  EFEMERO         │ │  member      │                                     │
│  │  INATIVO_40D     │ │  removal     │                                     │
│  │  INATIVO_7D      │ │              │                                     │
│  │  {SUBSCRIPTION}  │ │  Arc support │                                     │
│  └──────────┬───────┘ └──────┬───────┘                                     │
│             │                │                                              │
│             ▼                ▼                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                        MDE API + Graph API                           │  │
│  │  security.microsoft.com/api/machines                                │  │
│  │  graph.microsoft.com/v1.0/groups                                    │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
MDE-DeviceGovernance/
├── config.json                             # Central configuration (fill credentials)
├── config/
│   └── subscription_mapping.csv           # Optional: explicit subscription list
│
├── 01-Core-Engine/
│   └── Invoke-MDE-DeviceLifecycle.ps1     # v3.0 lifecycle engine (650+ lines)
│
├── 02-Entra-Sync/
│   └── Invoke-EntraGroupSync.ps1          # v2.0 Entra sync (per-subscription groups)
│
├── 03-Deploy/
│   └── Deploy-MDE-DeviceGovernance.ps1    # 16-stage Azure infra deployer
│
├── 04-Azure-Policy/
│   ├── policy-definition.json             # AuditIfNotExists policy rule
│   └── Set-MDEDeviceTag.ps1               # Registry tag applier
│
├── 05-Scheduler/
│   ├── Run-Governance.ps1                 # Daily orchestration wrapper
│   └── Install-ScheduledTask.ps1          # Windows Scheduled Task installer
│
├── 06-Runbooks/
│   ├── Runbook-Lifecycle.ps1              # AA-native lifecycle wrapper
│   └── Runbook-EntraSync.ps1              # AA-native Entra sync wrapper
│
└── 07-Tests/
    └── Test-E2E.ps1                       # 14-test E2E validation suite
```

---

## Quick Start (3 Steps)

### Step 1 — Configure credentials

Edit `config.json` and fill in:
```json
{
  "autenticacao": {
    "tenantId":  "YOUR-TENANT-ID",
    "appId":     "YOUR-APP-REGISTRATION-CLIENT-ID",
    "appSecret": "YOUR-APP-REGISTRATION-SECRET"
  }
}
```

> **App Registration requires**: `Machine.ReadWrite.All` on the MDE API (`https://api.securitycenter.microsoft.com`).

### Step 2a — Local execution (Windows Scheduled Task)

```powershell
# Run in report-only mode first (safe)
.\05-Scheduler\Run-Governance.ps1 -ReportOnly

# Install as daily scheduled task (runs as SYSTEM at 06:00)
.\05-Scheduler\Install-ScheduledTask.ps1
```

### Step 2b — Cloud execution (Azure Automation)

```powershell
# Prerequisites: az login
.\03-Deploy\Deploy-MDE-DeviceGovernance.ps1
```

### Step 3 — Validate

```powershell
.\07-Tests\Test-E2E.ps1
```

---

## Configuration Reference

| Section | Key | Default | Description |
|---|---|---|---|
| `autenticacao` | `tenantId` | *(required)* | Azure AD Tenant ID |
| `autenticacao` | `appId` | *(required)* | App Registration Client ID |
| `autenticacao` | `appSecret` | *(required)* | App Registration Secret |
| `classificacao` | `diasInativo7d` | `7` | Days since last seen → INATIVO_7D |
| `classificacao` | `diasInativo40d` | `40` | Days since last seen → INATIVO_40D |
| `classificacao` | `horasEfemero` | `48` | Hours since first seen → EFEMERO |
| `execucao` | `reportOnly` | `true` | Safe mode — no tags applied |
| `entraSync` | `habilitado` | `true` | Run Entra group sync |
| `entraSync` | `prefixoGrupo` | `grp-mde-governance` | Group name prefix |
| `entraSync` | `incluirArc` | `true` | Include Azure Arc machines |
| `descoberta` | `autoDiscoverSubscriptions` | `true` | Discover all subscriptions via ARM |
| `agendamento` | `horarioExecucao` | `06:00` | Daily run time |
| `azureAutomation` | `habilitado` | `false` | Use Azure Automation Variables |

---

## Device Classification Rules (Priority Order)

| Priority | Tag Applied | Condition |
|:---:|---|---|
| 1 (highest) | `DUPLICADA_EXCLUIR` | Device shares `vmId` with another, has older `firstSeen` |
| 2 | `EFEMERO` | `firstSeen` < 48 hours ago (newly onboarded) |
| 3 | `INATIVO_40D` | `lastSeen` > 40 days ago |
| 4 | `INATIVO_7D` | `lastSeen` > 7 days ago |
| 5 (lowest) | `{subscriptionName}` | Active device, maps to its Azure subscription |

---

## MDE Device Groups Setup

After deployment, create device groups in [security.microsoft.com](https://security.microsoft.com) → **Settings → Endpoints → Device groups**:

| Group Name | KQL Condition |
|---|---|
| `EFEMERO` | `Tag contains "EFEMERO"` |
| `INATIVO_7D` | `Tag contains "INATIVO_7D"` |
| `INATIVO_40D` | `Tag contains "INATIVO_40D"` |
| `DUPLICADA_EXCLUIR` | `Tag contains "DUPLICADA_EXCLUIR"` |
| `{subscriptionName}` | `AzureSubscriptionId in ('<subscription-id>')` |

> **Tip**: After deployment, the 16th stage generates a ready-to-use HTML guide at `Relatorios/MDE-DeviceGroups-SetupGuide-{DATE}.html`.

---

## What Changed vs Previous Projects

### vs MDE-ServerTags v2.2

| Feature | v2.2 | v3.0 |
|---|---|---|
| Lifecycle thresholds | Hardcoded (7d/40d/48h) | **Configurable via config.json** |
| Azure Automation support | None | **Full: AA Variables + Managed Identity** |
| Entra ID sync | None | **Per-subscription groups + stale removal** |
| Offboard report | None | **CSV export of INATIVO_40D + DUPLICADA** |
| Webhook notifications | None | **HTTP POST to Teams/Slack/Logic Apps** |
| Auth for ARM (sub discovery) | client_credentials only | **MI via IMDS first, fallback to creds** |

### vs MDE-PolicyAutomation v1.0.4

| Feature | v1.0.4 | v3.0 |
|---|---|---|
| Device lifecycle | None | **Full 5-priority classification** |
| Entra ID groups | 1 global group | **One group per subscription** |
| Stale member removal | None | **Automatic removal when VM deleted** |
| Deployer stages | 14 | **16 (+ lifecycle runbook + AA Variables)** |
| On-prem execution | None | **Windows Scheduled Task support** |

---

## Requirements

- **PowerShell 7+** (pwsh)
- **Azure CLI** (`az`) — authenticated
- **App Registration** with `Machine.ReadWrite.All` on MDE API
- **Permissions** to create Resource Groups, Automation Accounts, Policy Assignments (for cloud deployment)
- **Microsoft Graph** — `Group.ReadWrite.All`, `Device.Read.All` (for Entra sync)

---

## Related Projects

| Repository | Status | Role |
|---|---|---|
| [MDE-ServerTagsBySubscription](https://github.com/rfranca777/MDE-ServerTagsBySubscription) | ✅ Active — v3.0.0 | **Companion** — lightweight subscription-based tagging for Windows Server environments (PS5.1 compatible). Use when you need only server classification without Entra sync or Azure Automation. |
| [MDE-PolicyAutomation](https://github.com/rfranca777/MDE-PolicyAutomation) | ✅ Active — v1.0.4 | **Predecessor** — Azure Policy + Intune + MDE governance framework. Core components integrated and extended into this project. |
| [MDE-ServerTags](https://github.com/rfranca777/MDE-ServerTags) | 🗄️ **[LEGACY — archived]** | Superseded by MDE-ServerTagsBySubscription v3.0.0 and MDE-DeviceGovernance v3.0.0. |

> **Which project should I use?**
> - **Full enterprise governance** (Entra ID sync, Azure Automation, lifecycle runbooks, multi-subscription): use **this project** (`MDE-DeviceGovernance`)
> - **Lightweight server tagging only** (PS5.1, no cloud dependency, on-prem friendly): use [`MDE-ServerTagsBySubscription`](https://github.com/rfranca777/MDE-ServerTagsBySubscription)

---

## License

MIT — Rafael França | Microsoft Customer Success Account Manager (Cyber Security)

---

*MDE-DeviceGovernance v3.0.0 — the unified governance platform that supersedes MDE-ServerTags v2.2 and extends MDE-PolicyAutomation v1.0.4. For lightweight server-only tagging, see the companion project MDE-ServerTagsBySubscription.*

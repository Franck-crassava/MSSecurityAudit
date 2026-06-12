# MSSecurityAudit

> Automated Microsoft 365 & Defender for Endpoint security audit tool — generates a detailed HTML report and JSON export from your tenant.

![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-5391FE?logo=powershell&logoColor=white)
![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-API-0078D4?logo=microsoft&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

---

## What it audits

| Module | Checks |
|---|---|
| **Conditional Access** | Policy state, MFA enforcement, excluded users, sign-in risk |
| **MFA Coverage** | Registration rate per user, auth methods breakdown |
| **PIM / Privileged Roles** | Global Admin count, permanent assignments on critical roles |
| **Defender for Endpoint** | Device compliance, encryption, last sync, jailbreak detection |
| **Microsoft Secure Score** | Current score vs. max, displayed in report header |

---

## Output

- `output/MSSecurityAudit_YYYYMMDD_HHMM.html` — styled interactive report
- `output/MSSecurityAudit_YYYYMMDD_HHMM.json` — raw data export *(with `-ExportJson`)*

---

## Prerequisites

```powershell
# Install required modules (once)
Install-Module Microsoft.Graph -Scope CurrentUser
```

You need an account with at least these roles in the target tenant:
- **Global Reader** or **Security Reader**
- **Intune Administrator** *(for device compliance data)*

---

## Usage

```powershell
# Basic audit — HTML report only
.\scripts\Invoke-MSSecurityAudit.ps1 -TenantId "contoso.onmicrosoft.com"

# Full audit — HTML + JSON export
.\scripts\Invoke-MSSecurityAudit.ps1 -TenantId "contoso.onmicrosoft.com" -ExportJson

# Custom output folder
.\scripts\Invoke-MSSecurityAudit.ps1 -TenantId "contoso.onmicrosoft.com" -OutputPath "C:\Audits" -ExportJson
```

The script opens the HTML report automatically in your browser on Windows/macOS when the audit completes.

---

## Repo structure

```
MSSecurityAudit/
├── scripts/
│   └── Invoke-MSSecurityAudit.ps1   # Main audit script
├── docs/
│   └── report-template.html         # HTML report template (placeholders)
├── output/                          # Generated reports (git-ignored)
├── .gitignore
└── README.md
```

---

## Report preview

The HTML report includes:
- **KPI dashboard** — MFA coverage %, device compliance %, critical devices, Global Admin count, active CA policies
- **Conditional Access table** — per-policy score, MFA enforcement, findings
- **MFA gap list** — users without MFA registration
- **PIM assignments** — permanent privileged role holders
- **Device compliance table** — risk-colored rows (Critical / High / Medium / Low)

---

## Permissions requested (Graph scopes)

| Scope | Purpose |
|---|---|
| `Policy.Read.All` | Read Conditional Access policies |
| `Directory.Read.All` | Read users and role assignments |
| `AuditLog.Read.All` | Read sign-in and audit logs |
| `PrivilegedAccess.Read.AzureAD` | Read PIM role assignments |
| `DeviceManagementManagedDevices.Read.All` | Read Intune/Defender device data |
| `SecurityEvents.Read.All` | Read Secure Score |
| `User.Read.All` | Read user auth methods |

All scopes are **read-only**. The script makes no changes to your tenant.

---

## Roadmap

- [ ] Azure AD Identity Protection risk detections
- [ ] Microsoft Defender for Cloud (CSPM) integration
- [ ] Email delivery of report via SendGrid / Graph Mail
- [ ] Scheduled execution via Azure Automation Runbook
- [ ] Comparison between two audit snapshots (delta report)

---

## Author

**Franck Crassava** — Microsoft Security Engineer · Azure · Entra ID · M365  
[linkedin.com/in/franck-crassava](https://linkedin.com/in/franck-crassava)

---

## License

MIT — free to use, modify, and distribute.
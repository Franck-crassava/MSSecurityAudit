#Requires -Version 7.0
<#
.SYNOPSIS
    MSSecurityAudit — Microsoft 365 & Defender for Endpoint Security Audit

.DESCRIPTION
    Connects to Microsoft Graph and collects security posture data across:
      - Entra ID : Conditional Access, MFA coverage, PIM roles
      - Defender for Endpoint : device compliance, encryption, sync status
    Outputs a styled HTML report and a JSON export.

.PARAMETER TenantId
    Azure AD Tenant ID (GUID or domain, e.g. contoso.onmicrosoft.com)

.PARAMETER OutputPath
    Destination folder for report files. Default: ./output

.PARAMETER ExportJson
    Also export raw audit data as JSON alongside the HTML report.

.EXAMPLE
    .\Invoke-MSSecurityAudit.ps1 -TenantId "contoso.onmicrosoft.com" -ExportJson

.NOTES
    Author  : Franck Crassava
    GitHub  : https://github.com/franck-crassava/MSSecurityAudit
    Version : 1.0.0
    Requires: Install-Module Microsoft.Graph -Scope CurrentUser
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "./output",

    [switch]$ExportJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

function Write-Step  { param([string]$m) Write-Host "`n[>] $m" -ForegroundColor Cyan }
function Write-Ok    { param([string]$m) Write-Host "    [+] $m" -ForegroundColor Green }
function Write-Warn  { param([string]$m) Write-Host "    [!] $m" -ForegroundColor Yellow }
function Write-Fail  { param([string]$m) Write-Host "    [-] $m" -ForegroundColor Red }

function Ensure-OutputDir {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
}

# ─────────────────────────────────────────────────────────────
# CONNECTION
# ─────────────────────────────────────────────────────────────

function Connect-AuditGraph {
    Write-Step "Connecting to Microsoft Graph..."
    $scopes = @(
        "Policy.Read.All",
        "Directory.Read.All",
        "AuditLog.Read.All",
        "PrivilegedAccess.Read.AzureAD",
        "DeviceManagementManagedDevices.Read.All",
        "SecurityEvents.Read.All",
        "User.Read.All"
    )
    Connect-MgGraph -TenantId $TenantId -Scopes $scopes -NoWelcome
    Write-Ok "Connected to: $TenantId"
}

# ─────────────────────────────────────────────────────────────
# MODULE 1 — CONDITIONAL ACCESS
# ─────────────────────────────────────────────────────────────

function Get-ConditionalAccessAudit {
    Write-Step "Auditing Conditional Access policies..."
    $policies = Get-MgIdentityConditionalAccessPolicy -All

    $results = foreach ($p in $policies) {
        $score    = 0
        $findings = @()

        $hasMfa = $p.GrantControls.BuiltInControls -contains "mfa"
        if ($hasMfa) { $score += 30; $findings += "MFA enforced" }
        else          { $findings += "WARNING: No MFA grant control" }

        switch ($p.State) {
            "enabled"                            { $score += 20 }
            "enabledForReportingButNotEnforced"  { $score += 10; $findings += "WARNING: Report-only mode" }
            default                              { $findings += "WARNING: Policy disabled" }
        }

        if ($p.Conditions.Users.IncludeUsers -contains "All") {
            $score += 20; $findings += "Applies to all users"
        } else {
            $findings += "INFO: Scoped to specific users/groups"
        }

        $excCount = ($p.Conditions.Users.ExcludeUsers).Count
        if ($excCount -gt 3) { $findings += "WARNING: $excCount users excluded" }

        if ($p.Conditions.SignInRiskLevels.Count -gt 0) {
            $score += 30; $findings += "Sign-in risk evaluated"
        }

        [PSCustomObject]@{
            PolicyName    = $p.DisplayName
            State         = $p.State
            MfaEnforced   = $hasMfa
            AllUsers      = ($p.Conditions.Users.IncludeUsers -contains "All")
            ExcludedUsers = $excCount
            RiskEvaluated = ($p.Conditions.SignInRiskLevels.Count -gt 0)
            Score         = [Math]::Min($score, 100)
            Findings      = $findings -join " | "
            ModifiedAt    = $p.ModifiedDateTime
        }
    }

    Write-Ok "$($results.Count) CA policies audited"
    return $results
}

# ─────────────────────────────────────────────────────────────
# MODULE 2 — MFA COVERAGE
# ─────────────────────────────────────────────────────────────

function Get-MfaAudit {
    Write-Step "Auditing MFA registration coverage..."
    $users   = Get-MgUser -All -Property "DisplayName,UserPrincipalName,AccountEnabled"
    $enabled = $users | Where-Object { $_.AccountEnabled }
    $data    = @()
    $i       = 0

    foreach ($u in $enabled) {
        $i++
        if ($i % 25 -eq 0) { Write-Host "    Processing $i / $($enabled.Count)..." -ForegroundColor DarkGray }

        try {
            $methods     = Get-MgUserAuthenticationMethod -UserId $u.Id
            $hasMfa      = $methods.Count -gt 1
            $methodNames = $methods | ForEach-Object { $_.AdditionalProperties["@odata.type"] -replace "#microsoft.graph.", "" }
        } catch {
            $hasMfa = $false; $methods = @(); $methodNames = @("error")
        }

        $data += [PSCustomObject]@{
            DisplayName       = $u.DisplayName
            UserPrincipalName = $u.UserPrincipalName
            MfaRegistered     = $hasMfa
            MethodCount       = $methods.Count
            Methods           = $methodNames -join ", "
        }
    }

    $mfaOn   = ($data | Where-Object { $_.MfaRegistered }).Count
    $mfaOff  = ($data | Where-Object { -not $_.MfaRegistered }).Count
    $pct     = if ($data.Count -gt 0) { [Math]::Round($mfaOn / $data.Count * 100, 1) } else { 0 }

    Write-Ok "MFA coverage: $pct% ($mfaOn / $($data.Count))"
    if ($pct -lt 90) { Write-Warn "Coverage below 90% threshold" }

    return @{ Users = $data; Coverage = $pct; Total = $data.Count; Enabled = $mfaOn; Disabled = $mfaOff }
}

# ─────────────────────────────────────────────────────────────
# MODULE 3 — PIM
# ─────────────────────────────────────────────────────────────

function Get-PimAudit {
    Write-Step "Auditing PIM privileged role assignments..."

    $criticalRoles = @(
        "Global Administrator", "Security Administrator",
        "Privileged Role Administrator", "Exchange Administrator",
        "SharePoint Administrator", "Conditional Access Administrator",
        "Intune Administrator"
    )

    $assignments = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty "Principal,RoleDefinition"
    $results     = foreach ($a in $assignments) {
        if ($a.RoleDefinition.DisplayName -notin $criticalRoles) { continue }
        [PSCustomObject]@{
            RoleName      = $a.RoleDefinition.DisplayName
            PrincipalName = $a.Principal.AdditionalProperties["displayName"]
            PrincipalUPN  = $a.Principal.AdditionalProperties["userPrincipalName"]
            PrincipalType = $a.Principal.AdditionalProperties["@odata.type"] -replace "#microsoft.graph.", ""
            AssignmentType = "Permanent"
            IsCritical    = ($a.RoleDefinition.DisplayName -eq "Global Administrator")
        }
    }

    $gaCount = ($results | Where-Object { $_.RoleName -eq "Global Administrator" }).Count
    if ($gaCount -gt 4) { Write-Warn "$gaCount Global Admins — Microsoft recommends max 4" }
    Write-Ok "$($results.Count) privileged assignments audited"
    return $results
}

# ─────────────────────────────────────────────────────────────
# MODULE 4 — DEFENDER FOR ENDPOINT COMPLIANCE
# ─────────────────────────────────────────────────────────────

function Get-DefenderComplianceAudit {
    Write-Step "Auditing Defender for Endpoint device compliance..."

    $devices = Get-MgDeviceManagementManagedDevice -All -Property @(
        "DeviceName","OperatingSystem","OsVersion","ComplianceState",
        "LastSyncDateTime","IsEncrypted","JailBroken","ManagementAgent",
        "UserPrincipalName","Manufacturer","Model","EnrolledDateTime"
    )

    $results = foreach ($d in $devices) {
        $sync = if ($d.LastSyncDateTime) {
            [Math]::Round(((Get-Date) - $d.LastSyncDateTime).TotalDays, 1)
        } else { 9999 }

        $risk = switch ($true) {
            ($d.JailBroken -eq "True")                                          { "Critical" }
            ($d.ComplianceState -eq "noncompliant" -and $sync -gt 30)          { "Critical" }
            ($d.ComplianceState -eq "noncompliant")                             { "High" }
            ($d.IsEncrypted -eq $false)                                         { "High" }
            ($sync -gt 14)                                                      { "Medium" }
            default                                                              { "Low" }
        }

        [PSCustomObject]@{
            DeviceName      = $d.DeviceName
            OS              = $d.OperatingSystem
            OsVersion       = $d.OsVersion
            ComplianceState = $d.ComplianceState
            IsEncrypted     = $d.IsEncrypted
            JailBroken      = $d.JailBroken
            DaysSinceSync   = $sync
            RiskLevel       = $risk
            UserUPN         = $d.UserPrincipalName
            Manufacturer    = $d.Manufacturer
            Model           = $d.Model
        }
    }

    $compliant    = ($results | Where-Object { $_.ComplianceState -eq "compliant" }).Count
    $noncompliant = ($results | Where-Object { $_.ComplianceState -eq "noncompliant" }).Count
    $critical     = ($results | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $pct          = if ($results.Count -gt 0) { [Math]::Round($compliant / $results.Count * 100, 1) } else { 0 }

    Write-Ok "Compliance: $pct% ($compliant / $($results.Count) devices)"
    if ($noncompliant -gt 0) { Write-Warn "$noncompliant non-compliant device(s)" }
    if ($critical -gt 0)     { Write-Fail "$critical critical risk device(s)" }

    return @{ Devices = $results; Total = $results.Count; Compliant = $compliant; NonCompliant = $noncompliant; Critical = $critical; Coverage = $pct }
}

# ─────────────────────────────────────────────────────────────
# SECURE SCORE
# ─────────────────────────────────────────────────────────────

function Get-SecureScore {
    Write-Step "Fetching Microsoft Secure Score..."
    try {
        $s = Get-MgSecuritySecureScore -Top 1 | Select-Object -First 1
        Write-Ok "Secure Score: $($s.CurrentScore) / $($s.MaxScore)"
        return $s
    } catch {
        Write-Warn "Could not fetch Secure Score: $_"
        return $null
    }
}

# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

Write-Host "`n╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host   "║      MSSecurityAudit v1.0.0               ║" -ForegroundColor Cyan
Write-Host   "║  M365 & Defender for Endpoint Audit       ║" -ForegroundColor Cyan
Write-Host   "╚══════════════════════════════════════════╝`n" -ForegroundColor Cyan

Ensure-OutputDir
Connect-AuditGraph

$ts           = Get-Date -Format "yyyyMMdd_HHmm"
$caData       = Get-ConditionalAccessAudit
$mfaData      = Get-MfaAudit
$pimData      = Get-PimAudit
$defenderData = Get-DefenderComplianceAudit
$secureScore  = Get-SecureScore

# ── Load and render HTML template ──
$templatePath = Join-Path $PSScriptRoot "../docs/report-template.html"
if (-not (Test-Path $templatePath)) {
    Write-Fail "Template not found at $templatePath — aborting HTML generation"
    exit 1
}

# Build table rows
$caRows  = ($caData | ForEach-Object {
    $sc = switch ($_.State) { "enabled" {"badge-ok"} "enabledForReportingButNotEnforced" {"badge-warn"} default {"badge-fail"} }
    $mf = if ($_.MfaEnforced) {"<span class='badge badge-ok'>MFA</span>"} else {"<span class='badge badge-fail'>No MFA</span>"}
    "<tr><td>$($_.PolicyName)</td><td><span class='badge $sc'>$($_.State)</span></td><td>$mf</td><td>$($_.ExcludedUsers)</td><td>$($_.Score)/100</td><td class='findings'>$($_.Findings)</td></tr>"
}) -join "`n"

$mfaRows = ($mfaData.Users | Where-Object { -not $_.MfaRegistered } | Select-Object -First 20 | ForEach-Object {
    "<tr class='risk-high'><td>$($_.DisplayName)</td><td>$($_.UserPrincipalName)</td><td><span class='badge badge-fail'>Not registered</span></td><td>$($_.MethodCount)</td></tr>"
}) -join "`n"

$pimRows = ($pimData | ForEach-Object {
    $cr = if ($_.IsCritical) {"risk-critical"} else {""}
    "<tr class='$cr'><td>$($_.RoleName)</td><td>$($_.PrincipalName)</td><td>$($_.PrincipalUPN)</td><td>$($_.PrincipalType)</td><td><span class='badge badge-warn'>$($_.AssignmentType)</span></td></tr>"
}) -join "`n"

$devRows = ($defenderData.Devices | Sort-Object RiskLevel | ForEach-Object {
    $rc = switch ($_.RiskLevel) {"Critical"{"risk-critical"} "High"{"risk-high"} "Medium"{"risk-medium"} default{""}}
    $cb = if ($_.ComplianceState -eq "compliant") {"<span class='badge badge-ok'>Compliant</span>"} else {"<span class='badge badge-fail'>$($_.ComplianceState)</span>"}
    $eb = if ($_.IsEncrypted) {"<span class='badge badge-ok'>Yes</span>"} else {"<span class='badge badge-fail'>No</span>"}
    "<tr class='$rc'><td>$($_.DeviceName)</td><td>$($_.OS)</td><td>$($_.OsVersion)</td><td>$cb</td><td>$eb</td><td>$($_.DaysSinceSync)d</td><td><span class='badge badge-$($_.RiskLevel.ToLower())'>$($_.RiskLevel)</span></td><td>$($_.UserUPN)</td></tr>"
}) -join "`n"

$ssScore = if ($secureScore) { "$($secureScore.CurrentScore) / $($secureScore.MaxScore)" } else { "N/A" }
$ssPct   = if ($secureScore) { "$([Math]::Round($secureScore.CurrentScore/$secureScore.MaxScore*100,1))%" } else { "N/A" }
$gaCount = ($pimData | Where-Object { $_.RoleName -eq "Global Administrator" }).Count
$activeCA = ($caData | Where-Object { $_.State -eq "enabled" }).Count

$html = (Get-Content $templatePath -Raw) `
    -replace "{{TENANT_ID}}",       $TenantId `
    -replace "{{TIMESTAMP}}",       (Get-Date -Format "yyyy-MM-dd HH:mm") `
    -replace "{{SECURE_SCORE}}",    $ssScore `
    -replace "{{SECURE_SCORE_PCT}}",$ssPct `
    -replace "{{MFA_COVERAGE}}",    $mfaData.Coverage `
    -replace "{{MFA_DISABLED}}",    $mfaData.Disabled `
    -replace "{{DEVICE_COVERAGE}}", $defenderData.Coverage `
    -replace "{{DEVICE_CRITICAL}}", $defenderData.Critical `
    -replace "{{GA_COUNT}}",        $gaCount `
    -replace "{{CA_ACTIVE}}",       $activeCA `
    -replace "{{CA_TOTAL}}",        $caData.Count `
    -replace "{{MFA_ROWS}}",        $mfaRows `
    -replace "{{CA_ROWS}}",         $caRows `
    -replace "{{PIM_ROWS}}",        $pimRows `
    -replace "{{DEV_ROWS}}",        $devRows `
    -replace "{{DEVICE_TOTAL}}",    $defenderData.Total `
    -replace "{{PIM_TOTAL}}",       $pimData.Count

$htmlPath = Join-Path $OutputPath "MSSecurityAudit_${ts}.html"
$html | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Ok "HTML report → $htmlPath"

# JSON export
if ($ExportJson) {
    $jsonPath = Join-Path $OutputPath "MSSecurityAudit_${ts}.json"
    @{
        Meta              = @{ TenantId = $TenantId; GeneratedAt = (Get-Date -Format "o"); Version = "1.0.0" }
        SecureScore       = $secureScore
        MfaSummary        = @{ Coverage = $mfaData.Coverage; Total = $mfaData.Total; Enabled = $mfaData.Enabled; Disabled = $mfaData.Disabled }
        DefenderSummary   = @{ Coverage = $defenderData.Coverage; Total = $defenderData.Total; Compliant = $defenderData.Compliant; NonCompliant = $defenderData.NonCompliant; Critical = $defenderData.Critical }
        ConditionalAccess = $caData
        MfaUsers          = $mfaData.Users
        PimRoles          = $pimData
        Devices           = $defenderData.Devices
    } | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Ok "JSON export  → $jsonPath"
}

Write-Host "`n[✓] Audit complete!" -ForegroundColor Green
if ($IsWindows) { Start-Process $htmlPath }
elseif ($IsMacOS) { open $htmlPath }
<# 
CYBERSEAL6X Threat Exposure Analyzer (Branded) v1.1
Brought to you by CYBERSEAL6X Security Research
https://cyberseal6x.com

Outputs:
- TXT report
- JSON report
- HTML executive report (branded)
#>

param(
  [string]$OutRoot = "$env:PUBLIC\CYBERSEAL6X_Reports"
)

# ---------------- Branding ----------------
Clear-Host
$logo = @"
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗ █████╗ ██╗      ██████╗ ██╗  ██╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔══██╗██║     ██╔════╝ ╚██╗██╔╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗███████║██║     █████╗    ╚███╔╝
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══██║██║     ██╔══╝    ██╔██╗
╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║██║  ██║███████╗███████╗ ██╔╝ ██╗
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═╝  ╚═╝

            CYBERSEAL6X SECURITY RESEARCH PLATFORM
               Threat Exposure Analyzer v1.1
                https://cyberseal6x.com
"@

Write-Host $logo -ForegroundColor Green
Write-Host "Initializing CYBERSEAL6X Security Engine..." -ForegroundColor Cyan
Start-Sleep -Milliseconds 700
Write-Host ""

# ---------------- Output folder ----------------
$ErrorActionPreference = "SilentlyContinue"
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$OutDir = Join-Path $OutRoot "$env:COMPUTERNAME`_$ts"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# ---------------- Scoring ----------------
$score = 100
$findings = New-Object System.Collections.Generic.List[string]
$details  = [ordered]@{}

function Add-Finding([int]$deduct, [string]$title, [string]$detail) {
  $script:score -= $deduct
  $script:findings.Add("$title (-$deduct)")
  $script:details[$title] = $detail
}

# 1) Firewall
try {
  $fwDisabled = Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $false }
  if ($fwDisabled) {
    Add-Finding 15 "Firewall Disabled" ( ($fwDisabled | ForEach-Object { "$($_.Name) profile disabled" }) -join "; " )
  }
} catch {}

# 2) Microsoft Defender status (if present)
try {
  $mp = Get-MpComputerStatus
  if ($mp.RealTimeProtectionEnabled -eq $false) { Add-Finding 20 "Defender Real-Time Protection Off" "RealTimeProtectionEnabled=False" }
  if ($mp.IsTamperProtected -eq $false)         { Add-Finding 10 "Defender Tamper Protection Off" "IsTamperProtected=False" }
  $sigAge = (New-TimeSpan -Start $mp.AntivirusSignatureLastUpdated -End (Get-Date)).Days
  if ($sigAge -ge 7)                            { Add-Finding 10 "Defender Signatures Outdated" "Signature age = $sigAge days" }
} catch {
  $details["Defender"] = "Not available (3rd-party AV / permissions / server core)."
}

# 3) RDP enabled
try {
  $rdp = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections
  if ($rdp -eq 0) { Add-Finding 10 "RDP Enabled" "RDP is enabled. Confirm NLA, MFA, and access restrictions." }
} catch {}

# 4) SMBv1 enabled
try {
  $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
  if ($smb1.State -eq "Enabled") { Add-Finding 20 "SMBv1 Enabled" "Legacy SMBv1 increases risk (worm/lateral movement)." }
} catch {}

# 5) BitLocker (system drive)
try {
  $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive
  if ($bl.ProtectionStatus -ne "On") { Add-Finding 15 "Disk Encryption Off" "BitLocker protection is not ON for system drive." }
} catch {
  $details["BitLocker"] = "Not available (edition/permissions)."
}

# 6) Local admin count
try {
  $admins = Get-LocalGroupMember -Group "Administrators"
  if ($admins.Count -gt 3) { Add-Finding 10 "Too Many Local Admins" "Local Administrators count = $($admins.Count)." }
} catch {}

# 7) Weak PowerShell logging (best-effort checks)
try {
  $sb = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
  if (-not $sb -or $sb.EnableScriptBlockLogging -ne 1) { Add-Finding 10 "Script Block Logging Off" "Enable Script Block Logging for better detection." }
} catch {}

try {
  $mod = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue
  if (-not $mod -or $mod.EnableModuleLogging -ne 1) { Add-Finding 5 "Module Logging Off" "Enable Module Logging for better visibility." }
} catch {}

# 8) Unusual listening ports quick heuristic
try {
  $common = @(80,443,3389,445,135,139,53,22,25,110,143,389,636,1433,3306,5985,5986)
  $listen = Get-NetTCPConnection -State Listen | Select-Object LocalPort,OwningProcess -Unique
  $unusual = $listen | Where-Object { $common -notcontains $_.LocalPort } | Select-Object -First 20
  if ($unusual) {
    Add-Finding 5 "Unusual Listening Ports" ( ($unusual | ForEach-Object { "Port $($_.LocalPort) PID $($_.OwningProcess)" }) -join "; " )
  }
} catch {}

# Boundaries
if ($score -lt 0) { $score = 0 }
if ($score -gt 100) { $score = 100 }

# Risk level
if ($score -ge 85)      { $risk = "LOW" }
elseif ($score -ge 70)  { $risk = "MODERATE" }
elseif ($score -ge 50)  { $risk = "HIGH" }
else                    { $risk = "CRITICAL" }

# Meter
$percent = $score
$barsTotal = 20
$filled = [math]::Round(($percent/100)*$barsTotal)
$empty = $barsTotal - $filled
$meter = ("█" * $filled) + ("░" * $empty)

# Executive summary
$execSummary = @()
$execSummary += "Threat Exposure Score: $score / 100 ($risk)"
if ($findings.Count -eq 0) {
  $execSummary += "No major exposure indicators detected by this quick scan."
} else {
  $execSummary += "Top exposure indicators detected: " + (($findings | Select-Object -First 5) -join ", ")
  $execSummary += "Recommended next step: address the top 3 findings first for fastest risk reduction."
}

# ---------------- Console Output ----------------
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " CYBERSEAL6X Threat Exposure Score" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "System    : $env:COMPUTERNAME"
Write-Host "Time      : $(Get-Date)"
Write-Host ""
Write-Host ("Exposure  : " + $meter + "  " + $score + "%") -ForegroundColor Green
Write-Host ("Risk Level: " + $risk) -ForegroundColor Yellow
Write-Host ""

Write-Host "Key Findings:" -ForegroundColor Yellow
if ($findings.Count -eq 0) {
  Write-Host "- No major exposure indicators detected." -ForegroundColor Green
} else {
  foreach ($f in $findings) { Write-Host "- $f" }
}

Write-Host ""
Write-Host "Executive Summary:" -ForegroundColor Yellow
$execSummary | ForEach-Object { Write-Host "- $_" }

# ---------------- Write TXT + JSON + HTML ----------------
$txtReportPath = Join-Path $OutDir "CYBERSEAL6X_Threat_Exposure_Report.txt"
$jsonPath      = Join-Path $OutDir "CYBERSEAL6X_Threat_Exposure_Report.json"
$htmlPath      = Join-Path $OutDir "CYBERSEAL6X_Threat_Exposure_Report.html"

# TXT
$reportHeader = @"
========================================
CYBERSEAL6X SECURITY REPORT
Threat Exposure Analyzer v1.1
Brought to you by CYBERSEAL6X Security Research
https://cyberseal6x.com
========================================

"@

$txt = New-Object System.Collections.Generic.List[string]
$txt.Add($reportHeader)
$txt.Add("System            : $env:COMPUTERNAME")
$txt.Add("Generated On      : $(Get-Date)")
$txt.Add("Exposure Score    : $score / 100")
$txt.Add("Risk Level        : $risk")
$txt.Add("Exposure Meter    : $meter")
$txt.Add("")
$txt.Add("Executive Summary :")
$execSummary | ForEach-Object { $txt.Add(" - $_") }
$txt.Add("")
$txt.Add("Findings :")
if ($findings.Count -eq 0) { $txt.Add(" - None") } else { $findings | ForEach-Object { $txt.Add(" - $_") } }
$txt.Add("")
$txt.Add("Details :")
foreach ($k in $details.Keys) { $txt.Add(" - $k : $($details[$k])") }

$txt | Out-File -FilePath $txtReportPath -Encoding UTF8 -Width 400

# JSON
$payload = [ordered]@{
  ReportGeneratedBy = "CYBERSEAL6X Security Research"
  Tool              = "Threat Exposure Analyzer v1.1"
  Website           = "https://cyberseal6x.com"
  GeneratedOn       = (Get-Date).ToString("o")
  Computer          = $env:COMPUTERNAME
  Score             = $score
  RiskLevel         = $risk
  Findings          = @($findings)
  Details           = $details
  ExecutiveSummary  = $execSummary
}
($payload | ConvertTo-Json -Depth 6) | Out-File -FilePath $jsonPath -Encoding UTF8

# HTML (branded)
function HtmlEncode([string]$s) {
  if ($null -eq $s) { return "" }
  return [System.Net.WebUtility]::HtmlEncode($s)
}

$scorePct = [int]$score
$logoHtml = "<pre class='ascii'>" + (HtmlEncode($logo)) + "</pre>"

# Simple CSS class per risk
$riskClass = switch ($risk) {
  "LOW"      { "low" }
  "MODERATE" { "moderate" }
  "HIGH"     { "high" }
  default    { "critical" }
}

# Build findings HTML
if ($findings.Count -eq 0) {
  $findingsHtml = "<div class='ok'>No major exposure indicators detected.</div>"
} else {
  $items = ($findings | ForEach-Object { "<li>" + (HtmlEncode($_)) + "</li>" }) -join "`n"
  $findingsHtml = "<ul class='list'>$items</ul>"
}

# Details HTML
$detailsPairs = @()
foreach ($k in $details.Keys) {
  $detailsPairs += "<tr><td class='k'>" + (HtmlEncode($k)) + "</td><td class='v'>" + (HtmlEncode([string]$details[$k])) + "</td></tr>"
}
$detailsHtml = if ($detailsPairs.Count -gt 0) { "<table class='tbl'>" + ($detailsPairs -join "`n") + "</table>" } else { "<div class='muted'>No additional details.</div>" }

# Executive summary HTML
$execHtml = ($execSummary | ForEach-Object { "<li>" + (HtmlEncode($_)) + "</li>" }) -join "`n"

$html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>CYBERSEAL6X Threat Exposure Report</title>
<style>
  :root{
    --bg:#070a0f; --panel:#0c1220; --ink:#e9eefc; --muted:#a8b3d6;
    --line:#1b2a4a; --accent:#29ff7a; --cyan:#57d3ff; --warn:#ffd166; --bad:#ff4d6d;
  }
  body{ margin:0; font-family: ui-sans-serif, system-ui, Segoe UI, Roboto, Arial; background:var(--bg); color:var(--ink); }
  .wrap{ max-width:1100px; margin:0 auto; padding:28px 18px 60px; }
  .top{ display:flex; gap:16px; align-items:flex-start; flex-wrap:wrap; }
  .brand{ flex:1; min-width:320px; }
  .card{ background:linear-gradient(180deg, rgba(41,255,122,0.07), rgba(12,18,32,0.0)); border:1px solid var(--line); border-radius:16px; padding:16px; }
  .ascii{ margin:0; padding:14px; border-radius:14px; background:#050812; border:1px dashed rgba(41,255,122,0.35); color:var(--accent); overflow:auto; }
  .h1{ font-size:22px; font-weight:800; letter-spacing:0.4px; margin:0 0 8px; }
  .sub{ color:var(--muted); margin:0 0 14px; }
  .grid{ display:grid; grid-template-columns: repeat(12, 1fr); gap:14px; margin-top:14px; }
  .span6{ grid-column: span 6; }
  .span12{ grid-column: span 12; }
  @media (max-width: 900px){ .span6{ grid-column: span 12; } }
  .pill{ display:inline-flex; align-items:center; gap:8px; padding:6px 10px; border-radius:999px; border:1px solid var(--line); background:rgba(87,211,255,0.06); color:var(--cyan); font-weight:700; }
  .pill.low{ background:rgba(41,255,122,0.08); color:var(--accent); }
  .pill.moderate{ background:rgba(255,209,102,0.10); color:var(--warn); }
  .pill.high, .pill.critical{ background:rgba(255,77,109,0.10); color:var(--bad); }
  .kvs{ display:grid; grid-template-columns: 160px 1fr; gap:10px; margin-top:10px; }
  .kvk{ color:var(--muted); }
  .kvv{ font-weight:700; }
  .meter{ height:12px; border-radius:999px; background:#0a1020; border:1px solid var(--line); overflow:hidden; }
  .fill{ height:100%; width:${scorePct}%; background:linear-gradient(90deg, var(--accent), var(--cyan)); }
  .scoreLine{ display:flex; justify-content:space-between; gap:10px; margin-top:10px; color:var(--muted); }
  .scoreBig{ font-size:34px; font-weight:900; color:var(--ink); margin-top:6px; }
  .list{ margin:10px 0 0; padding-left:18px; color:var(--ink); }
  .ok{ padding:10px 12px; border-radius:12px; border:1px solid rgba(41,255,122,0.35); background:rgba(41,255,122,0.06); color:var(--accent); font-weight:700; }
  .muted{ color:var(--muted); }
  .tbl{ width:100%; border-collapse:collapse; margin-top:10px; }
  .tbl td{ border-top:1px solid var(--line); padding:10px 8px; vertical-align:top; }
  .tbl .k{ width:260px; color:var(--muted); font-weight:700; }
  .footer{ margin-top:18px; color:var(--muted); font-size:12px; }
  a{ color:var(--cyan); text-decoration:none; }
</style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div class="brand card">
        ${logoHtml}
        <div class="footer">
          Report generated by <b>CYBERSEAL6X Security Research</b> • <a href="https://cyberseal6x.com">cyberseal6x.com</a>
        </div>
      </div>

      <div class="card" style="min-width:320px; flex:1;">
        <div class="h1">Threat Exposure Report</div>
        <p class="sub">Executive-ready risk snapshot (0–100) based on common exposure indicators.</p>

        <div class="pill ${riskClass}">Risk Level: ${risk}</div>

        <div class="scoreBig">${score} / 100</div>

        <div class="meter"><div class="fill"></div></div>
        <div class="scoreLine">
          <span>Exposure Meter</span><span>${scorePct}%</span>
        </div>

        <div class="kvs">
          <div class="kvk">System</div><div class="kvv">${env:COMPUTERNAME}</div>
          <div class="kvk">Generated</div><div class="kvv">${(Get-Date)}</div>
          <div class="kvk">Tool</div><div class="kvv">Threat Exposure Analyzer v1.1</div>
        </div>
      </div>
    </div>

    <div class="grid">
      <div class="card span6">
        <div class="h1">Executive Summary</div>
        <ul class="list">
          ${execHtml}
        </ul>
      </div>

      <div class="card span6">
        <div class="h1">Key Findings</div>
        ${findingsHtml}
      </div>

      <div class="card span12">
        <div class="h1">Finding Details</div>
        <div class="muted">These are quick indicators for prioritization—validate in your environment before remediation changes.</div>
        ${detailsHtml}
      </div>

      <div class="card span12">
        <div class="h1">Brought to you by CYBERSEAL6X</div>
        <div class="muted">
          CYBERSEAL6X provides enterprise-grade cyber advisory, incident readiness, and AI security research solutions.
          Learn more at <a href="https://cyberseal6x.com">cyberseal6x.com</a>.
        </div>
      </div>
    </div>

    <div class="footer">
      Note: This tool is a rapid exposure snapshot. It does not replace full threat hunting, vulnerability management, or professional incident response.
    </div>
  </div>
</body>
</html>
"@

# IMPORTANT: Here-string variable expansion in HTML will try to interpret $env:COMPUTERNAME above,
# so we used ${env:COMPUTERNAME} (works because it's in scope). If your console complains, replace with $($env:COMPUTERNAME).
$html | Out-File -FilePath $htmlPath -Encoding UTF8

Write-Host ""
Write-Host "✅ Reports saved (CYBERSEAL6X branded):" -ForegroundColor Cyan
Write-Host "Folder: $OutDir" -ForegroundColor DarkGray
Write-Host "TXT   : $txtReportPath" -ForegroundColor DarkGray
Write-Host "JSON  : $jsonPath" -ForegroundColor DarkGray
Write-Host "HTML  : $htmlPath" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Report brought to you by CYBERSEAL6X." -ForegroundColor Cyan
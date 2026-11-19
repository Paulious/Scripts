<#
.SYNOPSIS
    Intune Custom Compliance discovery script: Windows quality update "N-2" check.

.DESCRIPTION
    Works out how many monthly Patch Tuesday releases the device is behind, with no
    build numbers to maintain. Output is one line of compressed JSON, which is what
    Intune custom compliance expects. The matching rules file is
    QualityUpdateCompliance.rules.json.

    How it decides (default mode, no infrastructure needed):
      1. Latest release month  = month of the most recent Patch Tuesday (2nd Tuesday),
                                 worked out from today's date.
      2. Installed release month = the YYYY-MM label in the title of the newest
                                 successfully installed cumulative update that is
                                 actually in effect (read from Windows Update history).
      3. MonthsBehind = latest release month - installed release month.
      4. More than 2 behind = NonCompliant.

    Optional hardening (BaselineUrl): compare the UBR to a small JSON feed that you
    publish automatically. See the workflow notes. Leave it empty to run without it.

    Fail closed: any problem reads as State=Error, MonthsBehind=99 so the rules fail.
    Handled errors still exit 0 so Intune evaluates the JSON instead of showing a
    script failure.

    Runs as SYSTEM, Windows PowerShell 5.1, flat JSON only (no nested objects).

.NOTES
    Version : 1.0.0
    Test it on a pilot ring before you assign it to Conditional Access.
#>

# ----------------------------- Config -----------------------------
$ScriptVersion          = '1.0.0'
$MaxMonthsBehind        = 2      # N-2. More than this = NonCompliant
$PatchTuesdayGraceDays  = 0      # delay before a new Patch Tuesday counts as "latest"
$BaselineUrl            = ''     # optional https://.../qu-baseline.json  (empty = off)
$BaselineMaxAgeDays     = 45     # ignore the feed if older than this
$LocalResultPath        = Join-Path $env:ProgramData 'Compliance\QualityUpdateCompliance.json'
# ------------------------------------------------------------------

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# Titles we accept as an OS cumulative update (monthly), and titles we never accept.
$LcuRegex     = '^(?<y>\d{4})-(?<m>\d{2})\s+(?<kind>Cumulative Update Preview|Cumulative Update|Security Update|Hotpatch(?: Update)?)\b.*\bWindows (?:10|11)\b'
$ExcludeRegex = '\.NET|Framework|Adobe|Flash|Edge|Defender|Malicious|Server|Dynamic Update|Servicing Stack|Safe OS'

function Get-PatchTuesday {
    param([int]$Year, [int]$Month)
    $first  = [datetime]::new($Year, $Month, 1, 0, 0, 0, [DateTimeKind]::Utc)
    $offset = ((2 - [int]$first.DayOfWeek) + 7) % 7      # Tuesday = 2
    return $first.AddDays($offset + 7)                    # second Tuesday
}

function Get-LatestReleaseIndex {
    # Month index = year*12 + month. Patch Tuesday lands around 17:00 UTC.
    param([datetime]$NowUtc, [int]$GraceDays)
    $pt = (Get-PatchTuesday -Year $NowUtc.Year -Month $NowUtc.Month).AddHours(17).AddDays($GraceDays)
    $idx = ($NowUtc.Year * 12) + $NowUtc.Month
    if ($NowUtc -ge $pt) { return $idx }
    return ($idx - 1)
}

function ConvertTo-MonthLabel {
    param([int]$Index)
    $i = $Index - 1
    return ('{0:0000}-{1:00}' -f [int][math]::Floor($i / 12), (($i % 12) + 1))
}

function Get-UpdateHistory {
    # Primary source: Windows Update Agent history (COM).
    $session  = New-Object -ComObject 'Microsoft.Update.Session'
    $searcher = $session.CreateUpdateSearcher()
    $total    = [int]$searcher.GetTotalHistoryCount()
    if ($total -le 0) { return @() }
    $count = [Math]::Min($total, 1000)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($e in $searcher.QueryHistory(0, $count)) {
        if ($null -eq $e -or [string]::IsNullOrWhiteSpace([string]$e.Title)) { continue }
        # The WUA history date is UTC.
        $out.Add([pscustomobject]@{
            Title     = [string]$e.Title
            Date      = [datetime]::SpecifyKind([datetime]$e.Date, [DateTimeKind]::Utc)
            Result    = [int]$e.ResultCode      # 2 = succeeded
            Operation = [int]$e.Operation       # 1 = install, 2 = uninstall
        })
    }
    return $out.ToArray()
}

function Get-UpdateHistoryFromEventLog {
    # Fallback (also works under Constrained Language Mode): event 19 = install succeeded.
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-WindowsUpdateClient/Operational'; Id = 19
    } -ErrorAction Stop
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($e in $events) {
        $title = $null
        try { $title = [string]$e.Properties[0].Value } catch { }
        if ([string]::IsNullOrWhiteSpace($title) -and $e.Message -match 'following update:\s*(.+)$') { $title = $Matches[1].Trim() }
        if ([string]::IsNullOrWhiteSpace($title)) { continue }
        $out.Add([pscustomobject]@{
            Title = $title; Date = $e.TimeCreated.ToUniversalTime(); Result = 2; Operation = 1
        })
    }
    return $out.ToArray()
}

function Get-BaselineStatus {
    # Optional UBR check against a published feed:
    # { "generatedUtc": "2026-11-10T20:00:00Z", "builds": { "26100": { "minUbr": 6584 } } }
    param([string]$Url, [int]$Build, [int]$Ubr, [int]$MaxAgeDays, [datetime]$NowUtc)
    $r = @{ Status = 'NotConfigured'; MinUbr = 0 }
    if ([string]::IsNullOrWhiteSpace($Url)) { return $r }
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $b   = Invoke-RestMethod -Uri $Url -UseBasicParsing -TimeoutSec 20
        $gen = ([datetime]$b.generatedUtc).ToUniversalTime()
        if (($NowUtc - $gen).TotalDays -gt $MaxAgeDays) { $r.Status = 'Stale'; return $r }
        $prop = $b.builds.PSObject.Properties[[string]$Build]
        if ($null -eq $prop) { $r.Status = 'NoEntryForBuild'; return $r }
        $r.MinUbr = [int]$prop.Value.minUbr
        $r.Status = $(if ($Ubr -ge $r.MinUbr) { 'Pass' } else { 'Fail' })
    }
    catch { $r.Status = 'Unreachable' }
    return $r
}

# ----------------------------- Main -----------------------------
$nowUtc = (Get-Date).ToUniversalTime()

$result = [ordered]@{
    QualityUpdateState                  = 'Error'
    ComplianceReason                    = ''
    MonthsBehind                        = 99
    OsName                              = ''
    OsVersion                           = ''
    OsDisplayVersion                    = ''
    BuildNumber                         = 0
    Ubr                                 = 0
    LatestReleaseMonth                  = ConvertTo-MonthLabel (Get-LatestReleaseIndex -NowUtc $nowUtc -GraceDays $PatchTuesdayGraceDays)
    LatestCumulativeUpdateTitle         = ''
    LatestCumulativeUpdateKb            = ''
    LatestCumulativeUpdateMonth         = ''
    LatestCumulativeUpdateInstalledUtc  = ''
    LastWindowsUpdateInstallUtc         = ''
    DaysSinceLastWindowsUpdateInstall   = 9999
    PendingRebootAffectsLcu             = $false
    BaselineCheck                       = 'NotConfigured'
    HistorySource                       = ''
    CheckedUtc                          = $nowUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
    ScriptVersion                       = $ScriptVersion
}

try {
    # --- OS facts (registry is the source of truth for build and UBR) ---
    $cv    = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = [int]$cv.CurrentBuildNumber
    $ubr   = [int]$cv.UBR
    $result.BuildNumber      = $build
    $result.Ubr              = $ubr
    $result.OsName           = $(if ($build -ge 22000) { 'Windows 11' } else { 'Windows 10' })
    $result.OsVersion        = ('10.0.{0}.{1}' -f $build, $ubr)
    $result.OsDisplayVersion = $(if ($cv.DisplayVersion) { [string]$cv.DisplayVersion } else { [string]$cv.ReleaseId })

    # --- Update history ---
    $history = @()
    try   { $history = @(Get-UpdateHistory); $result.HistorySource = 'WindowsUpdateHistory' }
    catch { $history = @() }
    if (-not ($history | Where-Object { $_.Title -match $LcuRegex })) {
        try   { $history = @(Get-UpdateHistoryFromEventLog); $result.HistorySource = 'EventLog' }
        catch { throw 'No update history available (Windows Update history and event log both failed or empty)' }
    }

    # --- Last successful Windows Update install (OS related, ignores Defender definitions etc.) ---
    $osInstalls = @($history | Where-Object {
        $_.Operation -eq 1 -and $_.Result -eq 2 -and
        $_.Title -match '\bWindows (?:10|11)\b' -and $_.Title -notmatch 'Defender|Malicious|Security Intelligence'
    })
    $lastInstall = $null
    if ($osInstalls.Count -gt 0) { $lastInstall = ($osInstalls | Sort-Object Date -Descending | Select-Object -First 1).Date }
    if ($null -eq $lastInstall) {
        $reg = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install'
        $t = (Get-ItemProperty -Path $reg -Name LastSuccessTime -ErrorAction SilentlyContinue).LastSuccessTime
        if ($t) { $lastInstall = [datetime]::SpecifyKind([datetime]$t, [DateTimeKind]::Utc) }
    }
    if ($null -ne $lastInstall) {
        $result.LastWindowsUpdateInstallUtc       = $lastInstall.ToString('yyyy-MM-ddTHH:mm:ssZ')
        $result.DaysSinceLastWindowsUpdateInstall = [int][math]::Max(0, [math]::Floor(($nowUtc - $lastInstall).TotalDays))
    }

    # --- Cumulative updates that count ---
    $removed = @($history | Where-Object { $_.Operation -eq 2 -and $_.Result -eq 2 })
    $lcus = New-Object System.Collections.Generic.List[object]
    foreach ($h in $history) {
        if ($h.Operation -ne 1 -or $h.Result -ne 2) { continue }
        if ($h.Title -match $ExcludeRegex)          { continue }
        $m = [regex]::Match($h.Title, $LcuRegex)
        if (-not $m.Success)                        { continue }
        $kb = [regex]::Match($h.Title, 'KB\d{6,8}').Value
        if ($kb -and ($removed | Where-Object { $_.Title -match $kb -and $_.Date -gt $h.Date })) { continue }   # rolled back
        $labelIdx = ([int]$m.Groups['y'].Value * 12) + [int]$m.Groups['m'].Value
        # A "Preview" released in month M carries the security fixes of Patch Tuesday M-1.
        $secIdx = $(if ($m.Groups['kind'].Value -like '*Preview') { $labelIdx - 1 } else { $labelIdx })
        $lcus.Add([pscustomobject]@{ Title = $h.Title; Kb = $kb; Date = $h.Date; LabelIdx = $labelIdx; SecIdx = $secIdx })
    }
    if ($lcus.Count -eq 0) { throw 'No cumulative update found in update history' }

    # An update installed after the last boot with a reboot pending is not in effect yet.
    $pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
               (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    $candidates = @($lcus | Sort-Object @{ Expression = 'SecIdx'; Descending = $true }, @{ Expression = 'Date'; Descending = $true })
    if ($pending) {
        $boot   = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()
        $inEffect = @($candidates | Where-Object { $_.Date -le $boot })
        if ($inEffect.Count -ne $candidates.Count) { $result.PendingRebootAffectsLcu = $true }
        $candidates = $inEffect
    }
    if ($candidates.Count -eq 0) { throw 'Newest cumulative update is installed but waiting for a reboot, no earlier one found' }
    $lcu = $candidates[0]

    $result.LatestCumulativeUpdateTitle        = $lcu.Title
    $result.LatestCumulativeUpdateKb           = $lcu.Kb
    $result.LatestCumulativeUpdateMonth        = ConvertTo-MonthLabel $lcu.LabelIdx
    $result.LatestCumulativeUpdateInstalledUtc = $lcu.Date.ToString('yyyy-MM-ddTHH:mm:ssZ')

    # --- The N-2 decision ---
    $latestIdx    = Get-LatestReleaseIndex -NowUtc $nowUtc -GraceDays $PatchTuesdayGraceDays
    $monthsBehind = [int][math]::Max(0, $latestIdx - $lcu.SecIdx)

    $base = Get-BaselineStatus -Url $BaselineUrl -Build $build -Ubr $ubr -MaxAgeDays $BaselineMaxAgeDays -NowUtc $nowUtc
    $result.BaselineCheck = $base.Status
    if ($base.Status -eq 'Fail') { $monthsBehind = [int][math]::Max($monthsBehind, $MaxMonthsBehind + 1) }

    $result.MonthsBehind = $monthsBehind
    if ($monthsBehind -gt $MaxMonthsBehind) {
        $result.QualityUpdateState = 'NonCompliant'
        $result.ComplianceReason   = if ($base.Status -eq 'Fail') {
            "UBR $ubr is below the N-2 baseline $($base.MinUbr) for build $build"
        } else {
            "$monthsBehind months behind (installed $($result.LatestCumulativeUpdateMonth), latest $($result.LatestReleaseMonth))"
        }
    }
    else {
        $result.QualityUpdateState = 'Compliant'
        $result.ComplianceReason   = "$monthsBehind months behind (installed $($result.LatestCumulativeUpdateMonth), latest $($result.LatestReleaseMonth))"
    }
}
catch {
    $result.QualityUpdateState = 'Error'
    $result.MonthsBehind       = 99
    $msg = [string]$_.Exception.Message
    $result.ComplianceReason   = 'Error: ' + $msg.Substring(0, [Math]::Min(200, $msg.Length))
}

$json = $result | ConvertTo-Json -Compress

# Local copy for support and audit. Never allowed to break the output.
try {
    $dir = Split-Path $LocalResultPath -Parent
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    Set-Content -Path $LocalResultPath -Value $json -Encoding UTF8 -Force
} catch { }

Write-Output $json
exit 0

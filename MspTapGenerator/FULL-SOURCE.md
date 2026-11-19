# MSP TAP Generator - full source

Every file in the project. Save each block under the path shown in its heading.

## Files

1. `Start-MspTapGenerator.ps1`
2. `Install-Prerequisites.ps1`
3. `Build-Package.ps1`
4. `src/Modules/MspTap.Core/MspTap.Core.psm1`
5. `src/Modules/MspTap.Data/MspTap.Data.psm1`
6. `src/Modules/MspTap.Graph/MspTap.Graph.psm1`
7. `src/UI/UiTypes.cs`
8. `src/UI/MainWindow.xaml`
9. `src/UI/Theme.Dark.xaml`
10. `src/UI/Theme.Light.xaml`
11. `src/UI/App.UI.ps1`
12. `tests/MspTap.Tests.ps1`
13. `samples/users.csv`
14. `samples/users_with_names.csv`
15. `.gitignore`
16. `README.md`
17. `docs/SECURITY.md`
18. `docs/GRAPH-PERMISSIONS.md`
19. `docs/ERROR-HANDLING.md`
20. `docs/APP-REGISTRATION.md`


---

## `Start-MspTapGenerator.ps1`

~~~~powershell
#Requires -Version 7.2
<#
.SYNOPSIS
    MSP TAP Generator - bulk Microsoft Entra Temporary Access Pass creation for Windows Autopilot onboarding.
.DESCRIPTION
    PowerShell 7 + WPF desktop application. Run on Windows only.
.EXAMPLE
    pwsh -STA -File .\Start-MspTapGenerator.ps1
#>
[CmdletBinding()]
param([switch]$NoRelaunch)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

if (-not $IsWindows) { Write-Error 'MSP TAP Generator is a Windows desktop application (WPF).'; exit 1 }

# WPF needs an STA thread.
if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA' -and -not $NoRelaunch) {
    & (Get-Process -Id $PID).Path -NoProfile -STA -File $PSCommandPath -NoRelaunch
    exit $LASTEXITCODE
}

# ---- prerequisite check (friendly failure instead of a stack trace)
$required = 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Users', 'Microsoft.Graph.Groups',
            'Microsoft.Graph.Identity.SignIns', 'Microsoft.Graph.Identity.DirectoryManagement', 'ImportExcel'
$missing = $required | Where-Object { -not (Get-Module -ListAvailable -Name $_) }
if ($missing) {
    $msg = "Missing PowerShell modules:`n  - $($missing -join "`n  - ")`n`nRun .\Install-Prerequisites.ps1 first."
    Write-Host $msg -ForegroundColor Red
    Add-Type -AssemblyName PresentationFramework
    [void][System.Windows.MessageBox]::Show($msg, 'MSP TAP Generator', 'OK', 'Error')
    exit 1
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml
if (-not ('MspTap.UserRow' -as [type])) { Add-Type -Path (Join-Path $root 'src\UI\UiTypes.cs') }

# Order matters: Core first (Data and Graph call into it).
$script:ModulePaths = @(
    Join-Path $root 'src\Modules\MspTap.Core\MspTap.Core.psm1'
    Join-Path $root 'src\Modules\MspTap.Data\MspTap.Data.psm1'
    Join-Path $root 'src\Modules\MspTap.Graph\MspTap.Graph.psm1'
)
foreach ($m in $script:ModulePaths) { Import-Module $m -Force -DisableNameChecking -Global }

. (Join-Path $root 'src\UI\App.UI.ps1')

try { Start-MspTapApp }
catch {
    Write-AppLog -Level Error -Category App -Message "Fatal: $($_.Exception.Message)"
    [void][System.Windows.MessageBox]::Show("The application hit a fatal error:`n`n$($_.Exception.Message)`n`nLogs: $(Get-LogDirectory)", 'MSP TAP Generator', 'OK', 'Error')
    exit 1
}
~~~~

---

## `Install-Prerequisites.ps1`

~~~~powershell
#Requires -Version 7.2
<#
.SYNOPSIS  Installs the PowerShell modules MSP TAP Generator needs (per-user by default, no admin rights).
.PARAMETER Scope  CurrentUser (default) or AllUsers (needs an elevated prompt).
#>
[CmdletBinding()]
param([ValidateSet('CurrentUser', 'AllUsers')][string]$Scope = 'CurrentUser')

$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'Windows only.' }

$modules = @(
    @{ Name = 'Microsoft.Graph.Authentication';                 Min = '2.10.0' }
    @{ Name = 'Microsoft.Graph.Users';                          Min = '2.10.0' }
    @{ Name = 'Microsoft.Graph.Groups';                         Min = '2.10.0' }
    @{ Name = 'Microsoft.Graph.Identity.SignIns';               Min = '2.10.0' }
    @{ Name = 'Microsoft.Graph.Identity.DirectoryManagement';   Min = '2.10.0' }
    @{ Name = 'ImportExcel';                                    Min = '7.8.0' }
)
if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
    Write-Host 'PSGallery is not trusted; you will be asked to confirm each install.' -ForegroundColor Yellow
}
foreach ($m in $modules) {
    $have = Get-Module -ListAvailable -Name $m.Name | Sort-Object Version -Descending | Select-Object -First 1
    if ($have -and $have.Version -ge [version]$m.Min) { Write-Host "OK       $($m.Name) $($have.Version)"; continue }
    Write-Host "Installing $($m.Name) (>= $($m.Min))..." -ForegroundColor Cyan
    Install-Module -Name $m.Name -MinimumVersion $m.Min -Scope $Scope -Repository PSGallery -AllowClobber -Force
}
Write-Host "`nAll prerequisites present. Start the app with: pwsh -STA -File .\Start-MspTapGenerator.ps1" -ForegroundColor Green
Write-Host 'Tip: keep all Microsoft.Graph.* modules on the SAME version to avoid assembly conflicts.'
~~~~

---

## `Build-Package.ps1`

~~~~powershell
#Requires -Version 7.2
<#
.SYNOPSIS  Lints, tests, (optionally signs) and packages MSP TAP Generator into dist\MspTapGenerator-<version>.zip
.PARAMETER Version         Package version (default: yyyy.MM.dd).
.PARAMETER CertThumbprint  If supplied, every .ps1/.psm1 is Authenticode-signed with this code-signing cert (Cert:\CurrentUser\My).
.PARAMETER SkipTests       Skip PSScriptAnalyzer + Pester.
#>
[CmdletBinding()]
param([string]$Version = (Get-Date -Format 'yyyy.MM.dd'), [string]$CertThumbprint, [switch]$SkipTests)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$stage = Join-Path $root "dist\stage\MspTapGenerator"
$zip = Join-Path $root "dist\MspTapGenerator-$Version.zip"

if (-not $SkipTests) {
    if (Get-Module -ListAvailable PSScriptAnalyzer) {
        $r = Invoke-ScriptAnalyzer -Path $root -Recurse -Severity Error -ExcludeRule PSAvoidUsingWriteHost,PSUseShouldProcessForStateChangingFunctions,PSUseApprovedVerbs,PSAvoidGlobalVars
        if ($r) { $r | Format-Table RuleName, Severity, ScriptName, Line, Message -AutoSize | Out-String | Write-Host; throw 'PSScriptAnalyzer reported issues.' }
    } else { Write-Warning 'PSScriptAnalyzer not installed - lint skipped.' }
    if (Get-Module -ListAvailable Pester) {
        $res = Invoke-Pester -Path (Join-Path $root 'tests') -PassThru -Output Minimal
        if ($res.FailedCount) { throw "$($res.FailedCount) Pester test(s) failed." }
    } else { Write-Warning 'Pester not installed - tests skipped.' }
}

if (Test-Path (Join-Path $root 'dist')) { Remove-Item (Join-Path $root 'dist') -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null
foreach ($item in 'src', 'docs', 'samples', 'Start-MspTapGenerator.ps1', 'Install-Prerequisites.ps1', 'README.md') {
    Copy-Item (Join-Path $root $item) $stage -Recurse -Force
}
Set-Content (Join-Path $stage 'Launch.cmd') -Encoding ASCII -Value '@echo off
pwsh.exe -NoProfile -STA -ExecutionPolicy RemoteSigned -File "%~dp0Start-MspTapGenerator.ps1"'
Set-Content (Join-Path $stage 'VERSION.txt') $Version

if ($CertThumbprint) {
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object Thumbprint -eq $CertThumbprint
    if (-not $cert) { throw "Certificate $CertThumbprint not found in Cert:\CurrentUser\My" }
    Get-ChildItem $stage -Recurse -Include *.ps1, *.psm1 | ForEach-Object {
        $s = Set-AuthenticodeSignature -FilePath $_.FullName -Certificate $cert -TimestampServer 'http://timestamp.digicert.com'
        if ($s.Status -ne 'Valid') { throw "Signing failed for $($_.Name): $($s.StatusMessage)" }
    }
    Write-Host 'Signed all scripts.' -ForegroundColor Green
}
Compress-Archive -Path $stage -DestinationPath $zip -Force
Remove-Item (Join-Path $root 'dist\stage') -Recurse -Force
Write-Host "Package: $zip" -ForegroundColor Green
(Get-FileHash $zip -Algorithm SHA256).Hash | Set-Content "$zip.sha256"
~~~~

---

## `src/Modules/MspTap.Core/MspTap.Core.psm1`

~~~~powershell
#Requires -Version 7.2
<#
  MspTap.Core
  Logging (with TAP scrubbing), settings, tenant profiles, retry/back-off,
  shared cross-runspace state. Contains NO Graph calls and stores NO credentials.
#>
Set-StrictMode -Version Latest

# ---------------------------------------------------------------- paths
function Get-AppDataRoot {
    $base = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { Join-Path $HOME '.local/share' }
    $p = Join-Path $base 'MspTapGenerator'
    if (-not (Test-Path $p)) { [void](New-Item -ItemType Directory -Path $p -Force) }
    $p
}
function Get-LogDirectory {
    $p = Join-Path (Get-AppDataRoot) 'Logs'
    if (-not (Test-Path $p)) { [void](New-Item -ItemType Directory -Path $p -Force) }
    $p
}

# ------------------------------------------- process-wide shared state
# AppDomain data is shared by every runspace in the process (UI + workers).
function Get-SharedState {
    $s = [AppDomain]::CurrentDomain.GetData('MspTap.State')
    if (-not $s) {
        $s = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new()
        [AppDomain]::CurrentDomain.SetData('MspTap.State', $s)
    }
    $s
}
function Set-SharedValue { param([string]$Name, $Value) (Get-SharedState)[$Name] = $Value }
function Get-SharedValue { param([string]$Name) $o = $null; if ((Get-SharedState).TryGetValue($Name, [ref]$o)) { $o } }
function Clear-SharedValue { param([string]$Name) $o = $null; [void](Get-SharedState).TryRemove($Name, [ref]$o) }

# ------------------------------------------------------ secret scrubbing
function Get-SecretRegistry {
    $r = [AppDomain]::CurrentDomain.GetData('MspTap.Secrets')
    if (-not $r) {
        $r = [System.Collections.Concurrent.ConcurrentDictionary[string, byte]]::new()
        [AppDomain]::CurrentDomain.SetData('MspTap.Secrets', $r)
    }
    $r
}
function Get-TextHash {
    param([string]$Text)
    [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($Text)))
}
function Register-LogSecret {
    # Only the SHA-256 hash is kept, never the value. Any token in a log line whose hash matches is redacted.
    param([string]$Value)
    if ($Value -and $Value.Length -ge 6) { [void](Get-SecretRegistry).TryAdd((Get-TextHash $Value), 1) }
}
function Clear-LogSecrets { (Get-SecretRegistry).Clear() }

function Protect-LogText {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $reg = Get-SecretRegistry
    if ($reg.Count -gt 0) {
        $Text = [regex]::Replace($Text, '[^\s"''`,;()\[\]{}<>=:.!?]{6,}', [System.Text.RegularExpressions.MatchEvaluator] {
            param($m) if ($reg.ContainsKey((Get-TextHash $m.Value))) { '[REDACTED]' } else { $m.Value } })
    }
    # JSON / key=value shapes of the TAP property, in case a Graph payload is echoed back
    $Text = [regex]::Replace($Text, '(?i)("?temporaryAccessPass"?\s*[:=]\s*"?)[^",\s}]+', '$1[REDACTED]')
    # bearer tokens
    $Text = [regex]::Replace($Text, '(?i)(bearer\s+)[A-Za-z0-9\-\._~\+/]+=*', '$1[REDACTED]')
    $Text = [regex]::Replace($Text, 'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]*', '[REDACTED-JWT]')
    $Text
}

# --------------------------------------------------------------- logging
$script:LogContext = @{ Session = [guid]::NewGuid().ToString('N').Substring(0, 8); Tenant = ''; TenantId = ''; Admin = ''; Ticket = '' }

function Set-LogContext {
    param([string]$Session, [string]$Tenant, [string]$TenantId, [string]$Admin, [string]$Ticket)
    if ($PSBoundParameters.ContainsKey('Ticket'))   { $script:LogContext.Ticket   = $Ticket }
    if ($PSBoundParameters.ContainsKey('Session'))  { $script:LogContext.Session  = $Session }
    if ($PSBoundParameters.ContainsKey('Tenant'))   { $script:LogContext.Tenant   = $Tenant }
    if ($PSBoundParameters.ContainsKey('TenantId')) { $script:LogContext.TenantId = $TenantId }
    if ($PSBoundParameters.ContainsKey('Admin'))    { $script:LogContext.Admin    = $Admin }
}
function Get-LogContext { $script:LogContext.Clone() }

function Write-AppLog {
    [CmdletBinding()]
    param(
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Audit')][string]$Level = 'Info',
        [ValidateSet('App', 'Auth', 'Graph', 'Import', 'Export', 'Validation', 'Generation', 'Policy', 'UI')][string]$Category = 'App',
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message
    )
    try {
        $rec = [ordered]@{
            ts       = (Get-Date).ToUniversalTime().ToString('o')
            level    = $Level
            category = $Category
            session  = $script:LogContext.Session
            tenant   = $script:LogContext.Tenant
            tenantId = $script:LogContext.TenantId
            admin    = $script:LogContext.Admin
            ticket   = $script:LogContext.Ticket
            message  = (Protect-LogText $Message)
        }
        $line = ($rec | ConvertTo-Json -Compress) + [Environment]::NewLine
        $file = Join-Path (Get-LogDirectory) ("mspTap_{0:yyyyMMdd}.jsonl" -f (Get-Date))
        $mutex = [System.Threading.Mutex]::new($false, 'Local\MspTapGenerator.Log')
        try {
            [void]$mutex.WaitOne(2000)
            [System.IO.File]::AppendAllText($file, $line, [System.Text.UTF8Encoding]::new($false))
        }
        finally { try { $mutex.ReleaseMutex() } catch { }; $mutex.Dispose() }
    }
    catch { <# logging must never break the app #> }
}

function Read-AppLog {
    # Returns newest-first records from the last N daily files.
    param([int]$Days = 7, [int]$Max = 5000)
    $out = [System.Collections.Generic.List[object]]::new()
    $files = Get-ChildItem (Get-LogDirectory) -Filter 'mspTap_*.jsonl' -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First $Days
    foreach ($f in $files) {
        $fs = [System.IO.File]::Open($f.FullName, 'Open', 'Read', 'ReadWrite')
        $sr = [System.IO.StreamReader]::new($fs)
        try {
            $lines = [System.Collections.Generic.List[string]]::new()
            while (-not $sr.EndOfStream) { $lines.Add($sr.ReadLine()) }
            for ($i = $lines.Count - 1; $i -ge 0; $i--) {
                try {
                    $o = $lines[$i] | ConvertFrom-Json
                    $out.Add([pscustomobject]@{
                        Time = ([datetime]$o.ts).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
                        Level = $o.level; Category = $o.category; Tenant = $o.tenant; Admin = $o.admin; Ticket = $(if ($o.PSObject.Properties['ticket']) { $o.ticket } else { '' }); Message = $o.message
                    })
                } catch { }
                if ($out.Count -ge $Max) { return $out }
            }
        }
        finally { $sr.Dispose(); $fs.Dispose() }
    }
    $out
}

function Remove-OldLogs {
    param([int]$RetentionDays = 90)
    Get-ChildItem (Get-LogDirectory) -Filter 'mspTap_*.jsonl' -ErrorAction SilentlyContinue |
        Where-Object LastWriteTime -lt (Get-Date).AddDays(-$RetentionDays) | Remove-Item -Force -ErrorAction SilentlyContinue
}

# -------------------------------------------------------------- settings
$script:DefaultSettings = [ordered]@{
    Theme                = 'System'          # System | Dark | Light
    ClientId             = '14d82eec-204b-4c2f-b7e8-296a70dab67e'   # Microsoft Graph Command Line Tools
    LogRetentionDays     = 90
    ClipboardClearSecs   = 60
    AutoHideTapSecs      = 30
    DefaultLifetimeMins  = 60
    RequireTicket        = $false           # true = block Validate/Generate until a ticket reference is entered
    RunInline            = $false            # compatibility mode: run Graph work on the UI thread
}
function Get-AppSettings {
    $file = Join-Path (Get-AppDataRoot) 'settings.json'
    $s = [ordered]@{} ; foreach ($k in $script:DefaultSettings.Keys) { $s[$k] = $script:DefaultSettings[$k] }
    if (Test-Path $file) {
        try {
            $j = Get-Content $file -Raw | ConvertFrom-Json
            foreach ($p in $j.PSObject.Properties) { if ($s.Contains($p.Name)) { $s[$p.Name] = $p.Value } }
        } catch { Write-AppLog -Level Warning -Message "settings.json unreadable, using defaults: $($_.Exception.Message)" }
    }
    [pscustomobject]$s
}
function Save-AppSettings {
    param([Parameter(Mandatory)]$Settings)
    $Settings | ConvertTo-Json | Set-Content (Join-Path (Get-AppDataRoot) 'settings.json') -Encoding UTF8
}

# -------------------------------------------------------- tenant profiles
# Name + tenant id only. No tokens, no secrets, no refresh tokens - ever.
function Test-TenantIdentifier {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $Value = $Value.Trim()
    $guid = [guid]::Empty
    if ([guid]::TryParse($Value, [ref]$guid)) { return $true }
    $Value -match '^(?=.{4,253}$)([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
}
function Get-TenantProfile {
    $file = Join-Path (Get-AppDataRoot) 'profiles.json'
    if (-not (Test-Path $file)) { return @() }
    try { @(Get-Content $file -Raw | ConvertFrom-Json) } catch { @() }
}
function Save-TenantProfile {
    param([Parameter(Mandatory)][string]$CustomerName, [Parameter(Mandatory)][string]$TenantId)
    if (-not (Test-TenantIdentifier $TenantId)) { throw "'$TenantId' is not a valid tenant ID (GUID) or domain name." }
    $list = @(Get-TenantProfile | Where-Object { $_.TenantId -ne $TenantId.Trim() })
    $list += [pscustomobject]@{ CustomerName = $CustomerName.Trim(); TenantId = $TenantId.Trim() }
    $list | Sort-Object CustomerName | ConvertTo-Json -AsArray | Set-Content (Join-Path (Get-AppDataRoot) 'profiles.json') -Encoding UTF8
    Write-AppLog -Category App -Message "Tenant profile saved: $CustomerName ($TenantId)"
}
function Remove-TenantProfile {
    param([Parameter(Mandatory)][string]$TenantId)
    $list = @(Get-TenantProfile | Where-Object { $_.TenantId -ne $TenantId })
    ConvertTo-Json -InputObject $list -AsArray | Set-Content (Join-Path (Get-AppDataRoot) 'profiles.json') -Encoding UTF8
}

# --------------------------------------------------------- misc helpers
function Test-UpnFormat { param([string]$Value) $Value -match '^[^@\s]+@[^@\s]+\.[^@\s]+$' }

function Get-LifetimeOption {
    @(
        [pscustomobject]@{ Label = '30 minutes'; Minutes = 30 }
        [pscustomobject]@{ Label = '1 hour';     Minutes = 60 }
        [pscustomobject]@{ Label = '4 hours';    Minutes = 240 }
        [pscustomobject]@{ Label = '8 hours';    Minutes = 480 }
        [pscustomobject]@{ Label = '24 hours';   Minutes = 1440 }
        [pscustomobject]@{ Label = '7 days';     Minutes = 10080 }
    )
}
function Format-Lifetime {
    param([int]$Minutes)
    $m = Get-LifetimeOption | Where-Object Minutes -eq $Minutes | Select-Object -First 1
    if ($m) { return $m.Label }
    if ($Minutes % 1440 -eq 0) { return "$($Minutes / 1440) days" }
    if ($Minutes % 60 -eq 0)   { return "$($Minutes / 60) hours" }
    "$Minutes minutes"
}

function Protect-ExportCell {
    # Neutralise spreadsheet formula injection (display names are attacker-influenced data).
    param([AllowNull()]$Value)
    if ($Value -is [string] -and $Value -match '^[=+\-@\t\r]') { return "'" + $Value }
    $Value
}

function ConvertFrom-SecureStringPlain {
    param([Parameter(Mandatory)][securestring]$Secure)
    $p = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Secure)
    try { [System.Runtime.InteropServices.Marshal]::PtrToStringUni($p) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($p) }
}

# ------------------------------------------------ errors + retry/back-off
function Get-ErrorStatusCode {
    param([Parameter(Mandatory)]$ErrorRecord)
    $ex = $ErrorRecord.Exception
    foreach ($path in @('Response.StatusCode', 'StatusCode')) {
        try {
            $v = $ex; foreach ($seg in $path.Split('.')) { $v = $v.$seg }
            if ($null -ne $v) { return [int]$v }
        } catch { }
    }
    $msg = "$($ex.Message) $($ErrorRecord.ErrorDetails.Message)"
    if ($msg -match 'TooManyRequests|\b429\b|throttl') { return 429 }
    if ($msg -match 'ServiceUnavailable|\b503\b') { return 503 }
    if ($msg -match 'GatewayTimeout|\b504\b') { return 504 }
    if ($msg -match 'Request_ResourceNotFound|ResourceNotFound|NotFound|\b404\b') { return 404 }
    if ($msg -match 'Authorization_RequestDenied|Forbidden|\b403\b|Insufficient privileges') { return 403 }
    if ($msg -match 'InvalidAuthenticationToken|Unauthorized|\b401\b') { return 401 }
    if ($msg -match 'BadRequest|\b400\b') { return 400 }
    0
}
function Get-RetryAfterSeconds {
    param($ErrorRecord)
    try {
        $h = $ErrorRecord.Exception.Response.Headers
        if ($h) {
            $v = $null
            if ($h.TryGetValues('Retry-After', [ref]$v)) { return [int](@($v)[0]) }
            if ($h['Retry-After']) { return [int]@($h['Retry-After'])[0] }
        }
    } catch { }
    $null
}
function Get-GraphErrorSummary {
    # One-line, scrubbed description: "Code: message"
    param([Parameter(Mandatory)]$ErrorRecord)
    $code = ''; $msg = $ErrorRecord.Exception.Message
    try {
        $raw = $ErrorRecord.ErrorDetails.Message
        if ($raw) {
            $j = $raw | ConvertFrom-Json -ErrorAction Stop
            if ($j.error.code)    { $code = $j.error.code }
            if ($j.error.message) { $msg = $j.error.message }
        }
    } catch { }
    $text = if ($code) { "${code}: $msg" } else { $msg }
    Protect-LogText (($text -replace '\s+', ' ').Trim())
}

function Invoke-WithRetry {
    <# Retries throttling (429) and transient 503/504 with exponential back-off + jitter,
       honouring Retry-After. Everything else is thrown immediately. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [int]$MaxAttempts = 6,
        [int]$BaseDelaySeconds = 2,
        [int]$MaxDelaySeconds = 60,
        [scriptblock]$OnRetry,
        $Cancel
    )
    for ($attempt = 1; ; $attempt++) {
        try { return & $ScriptBlock }
        catch {
            $status = Get-ErrorStatusCode $_
            $retryable = $status -in 429, 503, 504
            if (-not $retryable -or $attempt -ge $MaxAttempts) { throw }
            $after = Get-RetryAfterSeconds $_
            $delay = if ($after) { $after } else { [Math]::Min($MaxDelaySeconds, $BaseDelaySeconds * [Math]::Pow(2, $attempt - 1)) }
            $delay = [Math]::Min($MaxDelaySeconds, $delay) + (Get-Random -Minimum 0.0 -Maximum 1.0)
            Write-AppLog -Level Warning -Category Graph -Message ("HTTP {0} - retry {1}/{2} in {3:N1}s" -f $status, $attempt, ($MaxAttempts - 1), $delay)
            if ($OnRetry) { & $OnRetry $status $attempt $delay }
            $until = (Get-Date).AddSeconds($delay)
            while ((Get-Date) -lt $until) {
                if ($Cancel -and $Cancel.Cancel) { throw 'Cancelled' }
                Start-Sleep -Milliseconds 250
            }
        }
    }
}

Export-ModuleMember -Function *-*
~~~~

---

## `src/Modules/MspTap.Data/MspTap.Data.psm1`

~~~~powershell
#Requires -Version 7.2
<# MspTap.Data - CSV/XLSX import and XLSX export. Needs the ImportExcel module (no Excel install required). #>
Set-StrictMode -Version Latest

function Initialize-ExcelModule {
    if (-not (Get-Module ImportExcel)) {
        if (-not (Get-Module -ListAvailable ImportExcel)) {
            throw "The 'ImportExcel' module is not installed. Run Install-Prerequisites.ps1 or: Install-Module ImportExcel -Scope CurrentUser"
        }
        Import-Module ImportExcel -ErrorAction Stop
    }
}

$script:UpnAliases  = 'userprincipalname', 'upn', 'user principal name', 'username', 'user name', 'email', 'mail', 'e-mail', 'emailaddress'
$script:NameAliases = 'displayname', 'display name', 'name', 'fullname', 'full name'

function Find-ColumnName {
    param([string[]]$Columns, [string[]]$Aliases)
    foreach ($a in $Aliases) {
        $hit = $Columns | Where-Object { $_.Trim().ToLowerInvariant() -eq $a } | Select-Object -First 1
        if ($hit) { return $hit }
    }
    $null
}

function ConvertTo-UserRecord {
    <# Normalises raw rows -> unique, well-formed user records. Returns @{ Users; Skipped } #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][string]$UpnColumn,
        [string]$DisplayNameColumn,
        [string]$Source = 'File'
    )
    $users = [System.Collections.Generic.List[object]]::new()
    $skipped = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $n = 1
    foreach ($r in $Rows) {
        $n++
        $upn = "$($r.$UpnColumn)".Trim()
        $dn = if ($DisplayNameColumn) { "$($r.$DisplayNameColumn)".Trim() } else { '' }
        if (-not $upn -and -not $dn) { continue }   # blank line
        if (-not (Test-UpnFormat $upn)) { $skipped.Add([pscustomobject]@{ Row = $n; Value = $upn; Reason = 'Not a valid UPN / email format' }); continue }
        if (-not $seen.Add($upn)) { $skipped.Add([pscustomobject]@{ Row = $n; Value = $upn; Reason = 'Duplicate in file' }); continue }
        $users.Add([pscustomobject]@{ UserPrincipalName = $upn; DisplayName = $dn; Source = $Source })
    }
    @{ Users = $users.ToArray(); Skipped = $skipped.ToArray() }
}

function Import-UsersFromCsv {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "File not found: $Path" }
    if ((Get-Item -LiteralPath $Path).Length -gt 20MB) { throw 'CSV is larger than 20 MB - refusing to load.' }
    $first = Get-Content -LiteralPath $Path -TotalCount 1
    $delim = if ($first -match ';' -and $first -notmatch ',') { ';' } elseif ($first -match "`t" -and $first -notmatch ',') { "`t" } else { ',' }
    $rows = @(Import-Csv -LiteralPath $Path -Delimiter $delim)
    if ($rows.Count -eq 0) { throw 'The CSV contains no data rows.' }
    $cols = @($rows[0].PSObject.Properties.Name)
    $upnCol = Find-ColumnName $cols $script:UpnAliases
    if (-not $upnCol) { throw "No UserPrincipalName column found. Columns present: $($cols -join ', ')" }
    $nameCol = Find-ColumnName $cols $script:NameAliases
    ConvertTo-UserRecord -Rows $rows -UpnColumn $upnCol -DisplayNameColumn $nameCol -Source 'CSV'
}

# Excel may hold a lock on the workbook - always work on a temp copy.
function Copy-ToTemp {
    param([string]$Path)
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("msptap_{0}.xlsx" -f [guid]::NewGuid().ToString('N'))
    Copy-Item -LiteralPath $Path -Destination $tmp -Force
    $tmp
}

function Get-XlsxSheetName {
    param([Parameter(Mandatory)][string]$Path)
    Initialize-ExcelModule
    $tmp = Copy-ToTemp $Path
    try { @(Get-ExcelSheetInfo -Path $tmp | Where-Object { $_.State -ne 'VeryHidden' } | ForEach-Object Name) }
    finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}

function Get-XlsxColumnName {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Sheet)
    Initialize-ExcelModule
    $tmp = Copy-ToTemp $Path
    try {
        $pkg = Open-ExcelPackage -Path $tmp
        try {
            $ws = $pkg.Workbook.Worksheets[$Sheet]
            if (-not $ws -or -not $ws.Dimension) { return @() }
            @(1..$ws.Dimension.Columns | ForEach-Object { $ws.Cells[1, $_].Text } | Where-Object { $_ -and $_.Trim() })
        }
        finally { Close-ExcelPackage $pkg -NoSave }
    }
    finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}

function Import-UsersFromXlsx {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Sheet,
        [Parameter(Mandatory)][string]$UpnColumn,
        [string]$DisplayNameColumn
    )
    Initialize-ExcelModule
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "File not found: $Path" }
    $tmp = Copy-ToTemp $Path
    try { $rows = @(Import-Excel -Path $tmp -WorksheetName $Sheet) }
    finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    if ($rows.Count -eq 0) { throw "Sheet '$Sheet' contains no data rows." }
    ConvertTo-UserRecord -Rows $rows -UpnColumn $UpnColumn -DisplayNameColumn $DisplayNameColumn -Source 'XLSX'
}

function Get-TapExportFileName { 'TAPs_{0:yyyyMMdd_HHmmss}.xlsx' -f (Get-Date) }

function Export-TapResult {
    <#
      Rows: objects with UserPrincipalName, DisplayName, Tap ([securestring] or $null), TapLength,
            OneTimeUse, StartUtc, ExpiryUtc, Status.
      -MaskTap writes ******** instead of the real value (TAP never touches disk).
      -WorkbookPassword encrypts the xlsx (AES, EPPlus).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Rows,
        [Parameter(Mandatory)][string]$Path,
        [switch]$MaskTap,
        [string]$WorkbookPassword,
        [string]$Reference
    )
    Initialize-ExcelModule
    $data = foreach ($r in $Rows) {
        $tap = ''
        if ($r.Tap) { $tap = if ($MaskTap) { '********' } else { ConvertFrom-SecureStringPlain $r.Tap } }
        [pscustomobject][ordered]@{
            UserPrincipalName = Protect-ExportCell $r.UserPrincipalName
            DisplayName       = Protect-ExportCell $r.DisplayName
            TAP               = $tap
            TAPLength         = if ($r.TapLength) { [int]$r.TapLength } else { $null }
            OneTimeUse        = [bool]$r.OneTimeUse
            StartTime         = $r.StartUtc
            ExpiryTime        = $r.ExpiryUtc
            Status            = Protect-ExportCell $r.Status
        }
    }
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    $pkg = $data | Export-Excel -Path $Path -WorksheetName 'TAPs' -TableName 'TapResults' -TableStyle Medium2 `
        -AutoSize -FreezeTopRow -BoldTopRow -NoNumberConversion 'UserPrincipalName', 'TAP' -PassThru
    try {
        $ws = $pkg.Workbook.Worksheets['TAPs']
        foreach ($c in 6, 7) { $ws.Column($c).Style.Numberformat.Format = 'yyyy-mm-dd hh:mm:ss' }   # UTC
        $ws.Column(3).Style.Font.Name = 'Consolas'
        $ws.Cells[$ws.Dimension.Address].AutoFitColumns()
        $ws.Cells['A1'].AddComment('StartTime / ExpiryTime are UTC.', 'MspTap') | Out-Null
        $pkg.Workbook.Properties.Title = 'Temporary Access Passes'
        if ($Reference) { $pkg.Workbook.Properties.Subject = "Ticket / change: $Reference" }
    }
    finally {
        if ($WorkbookPassword) { Close-ExcelPackage $pkg -Password $WorkbookPassword } else { Close-ExcelPackage $pkg }
    }
    Write-AppLog -Level Success -Category Export -Message ("Exported {0} rows to {1} (TAP masked: {2}, encrypted: {3}, ticket: {4})" -f @($Rows).Count, (Split-Path $Path -Leaf), [bool]$MaskTap, [bool]$WorkbookPassword, $Reference)
}

function Export-FailureReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Rows, [Parameter(Mandatory)][string]$Path)
    Initialize-ExcelModule
    $data = foreach ($r in $Rows) {
        [pscustomobject][ordered]@{
            UserPrincipalName = Protect-ExportCell $r.UserPrincipalName
            DisplayName       = Protect-ExportCell $r.DisplayName
            Stage             = $r.Stage
            Detail            = Protect-ExportCell (Protect-LogText $r.Detail)
        }
    }
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    $data | Export-Excel -Path $Path -WorksheetName 'Failures' -TableName 'TapFailures' -TableStyle Medium3 -AutoSize -FreezeTopRow -BoldTopRow -NoNumberConversion 'UserPrincipalName'
    Write-AppLog -Category Export -Message ("Exported {0} failure rows to {1}" -f @($Rows).Count, (Split-Path $Path -Leaf))
}

Export-ModuleMember -Function *-*
~~~~

---

## `src/Modules/MspTap.Graph/MspTap.Graph.psm1`

~~~~powershell
#Requires -Version 7.2
<#
  MspTap.Graph - everything that talks to Microsoft Graph (via the Microsoft Graph PowerShell SDK).

  TAP values are converted to [securestring] the moment they leave the SDK object and are never
  passed to Write-AppLog. Batch functions report progress through an -Emit callback so they can run
  in a background runspace or inline.
#>
Set-StrictMode -Version Latest
Import-Module Microsoft.Graph.Authentication -MinimumVersion 2.10.0 -ErrorAction Stop

$script:RequiredScopes = @('User.Read.All', 'UserAuthenticationMethod.ReadWrite.All', 'Directory.Read.All', 'AuditLog.Read.All')
$script:PolicyReadScope = 'Policy.Read.All'
$script:PolicyWriteScope = 'Policy.ReadWrite.AuthenticationMethod'
$script:DefaultClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'

function Get-RequiredScope { $script:RequiredScopes }

function Initialize-TapGraphModule {
    # Heavy SDK sub-modules are loaded on demand (once per runspace).
    foreach ($m in 'Microsoft.Graph.Users', 'Microsoft.Graph.Groups', 'Microsoft.Graph.Identity.SignIns', 'Microsoft.Graph.Identity.DirectoryManagement') {
        if (-not (Get-Module $m)) { Import-Module $m -MinimumVersion 2.10.0 -ErrorAction Stop -DisableNameChecking }
    }
}

# ------------------------------------------------------------- tokens
function ConvertFrom-JwtPayload {
    param([string]$Jwt)
    try {
        $p = $Jwt.Split('.')[1].Replace('-', '+').Replace('_', '/')
        switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } }
        [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
    } catch { $null }
}

function Get-DesiredScope {
    param([bool]$PolicyRead = $true, [bool]$PolicyWrite = $false)
    $s = [System.Collections.Generic.List[string]]::new(); $s.AddRange($script:RequiredScopes)
    if ($PolicyRead -or $PolicyWrite) { $s.Add($script:PolicyReadScope) }
    if ($PolicyWrite) { $s.Add($script:PolicyWriteScope) }
    $s.ToArray()
}

# --------------------------------------------------------- authentication
function Connect-TapGraph {
    <#
      Interactive : Connect-MgGraph (browser / WAM), process-scoped context.
      DeviceCode  : native OAuth2 device-code flow so the code can be shown inside the GUI, then
                    Connect-MgGraph -AccessToken. Refresh token is kept in process memory only.
      -Emit receives ('devicecode', @{UserCode;Uri;ExpiresIn}) while waiting for the user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [ValidateSet('Interactive', 'DeviceCode')][string]$Method = 'Interactive',
        [string[]]$Scopes = $script:RequiredScopes,
        [string]$ClientId = $script:DefaultClientId,
        [scriptblock]$Emit,
        $Cancel
    )
    Initialize-TapGraphModule
    $TenantId = $TenantId.Trim()
    Write-AppLog -Category Auth -Message "Sign-in started ($Method) for tenant $TenantId"

    if ($Method -eq 'Interactive') {
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -Scopes $Scopes -ContextScope Process -NoWelcome -ErrorAction Stop | Out-Null
        Set-SharedValue 'AuthMethod' 'Interactive'
    }
    else {
        $scopeStr = (($Scopes | ForEach-Object { "https://graph.microsoft.com/$_" }) + 'offline_access') -join ' '
        $base = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0"
        $dc = Invoke-RestMethod -Method Post -Uri "$base/devicecode" -Body @{ client_id = $ClientId; scope = $scopeStr } -ErrorAction Stop
        if ($Emit) { & $Emit 'devicecode' @{ UserCode = $dc.user_code; Uri = $dc.verification_uri; ExpiresIn = [int]$dc.expires_in } }
        $interval = [Math]::Max(3, [int]$dc.interval)
        $deadline = (Get-Date).AddSeconds([int]$dc.expires_in)
        $tok = $null
        while (-not $tok) {
            if ($Cancel -and $Cancel.Cancel) { throw 'Sign-in cancelled.' }
            if ((Get-Date) -gt $deadline) { throw 'The device code expired before sign-in completed.' }
            Start-Sleep -Seconds $interval
            try {
                $tok = Invoke-RestMethod -Method Post -Uri "$base/token" -ErrorAction Stop -Body @{
                    grant_type = 'urn:ietf:params:oauth:grant-type:device_code'; client_id = $ClientId; device_code = $dc.device_code }
            }
            catch {
                $err = try { ($_.ErrorDetails.Message | ConvertFrom-Json).error } catch { 'unknown' }
                switch ($err) {
                    'authorization_pending' { }
                    'slow_down' { $interval += 5 }
                    'authorization_declined' { throw 'Sign-in was declined.' }
                    'expired_token' { throw 'The device code expired before sign-in completed.' }
                    default { throw "Device code sign-in failed: $err" }
                }
            }
        }
        Set-TokenState -Token $tok -TenantId $TenantId -ClientId $ClientId -Scopes $Scopes
        Connect-MgGraph -AccessToken (ConvertTo-SecureString $tok.access_token -AsPlainText -Force) -NoWelcome -ErrorAction Stop | Out-Null
        Set-SharedValue 'AuthMethod' 'DeviceCode'
    }
    Get-TapGraphIdentity
}

function Set-TokenState {
    param($Token, [string]$TenantId, [string]$ClientId, [string[]]$Scopes)
    Set-SharedValue 'RefreshToken' (ConvertTo-SecureString $Token.refresh_token -AsPlainText -Force)
    Set-SharedValue 'TokenExpiresUtc' ([datetime]::UtcNow.AddSeconds([int]$Token.expires_in))
    Set-SharedValue 'TokenTenant' $TenantId
    Set-SharedValue 'TokenClientId' $ClientId
    Set-SharedValue 'TokenScopes' $Scopes
    $claims = ConvertFrom-JwtPayload $Token.access_token
    if ($claims -and $claims.PSObject.Properties['scp']) { Set-SharedValue 'TokenGrantedScopes' @("$($claims.scp)" -split ' ' | Where-Object { $_ }) }
    if ($claims) {
        $who = if ($claims.PSObject.Properties['upn']) { $claims.upn } elseif ($claims.PSObject.Properties['unique_name']) { $claims.unique_name } else { '' }
        Set-SharedValue 'TokenAdmin' $who
    }
}

function Update-TapGraphToken {
    <# Device-code sessions only: refresh the access token shortly before it expires. Interactive sessions are refreshed by MSAL. #>
    if ((Get-SharedValue 'AuthMethod') -ne 'DeviceCode') { return }
    $exp = Get-SharedValue 'TokenExpiresUtc'
    if ($exp -and ($exp - [datetime]::UtcNow).TotalMinutes -gt 5) { return }
    $rt = Get-SharedValue 'RefreshToken'
    if (-not $rt) { throw 'Session expired - please sign in again.' }
    $tenant = Get-SharedValue 'TokenTenant'; $client = Get-SharedValue 'TokenClientId'; $scopes = Get-SharedValue 'TokenScopes'
    $scopeStr = (($scopes | ForEach-Object { "https://graph.microsoft.com/$_" }) + 'offline_access') -join ' '
    $tok = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -ErrorAction Stop -Body @{
        grant_type = 'refresh_token'; client_id = $client; scope = $scopeStr; refresh_token = (ConvertFrom-SecureStringPlain $rt) }
    Set-TokenState -Token $tok -TenantId $tenant -ClientId $client -Scopes $scopes
    Connect-MgGraph -AccessToken (ConvertTo-SecureString $tok.access_token -AsPlainText -Force) -NoWelcome -ErrorAction Stop | Out-Null
    Write-AppLog -Category Auth -Message 'Access token refreshed (device-code session).'
}

function Get-GrantedScope {
    # Access-token sign-ins may not populate Get-MgContext.Scopes; fall back to the token's own 'scp' claim.
    $ctx = Get-MgContext; $s = @()
    if ($ctx -and $ctx.Scopes) { $s = @($ctx.Scopes) }
    if ($s.Count -eq 0) { $g = Get-SharedValue 'TokenGrantedScopes'; if ($g) { $s = @($g) } }
    $s
}

function Get-TapGraphIdentity {
    $ctx = Get-MgContext
    if (-not $ctx) { return $null }
    Initialize-TapGraphModule
    $org = $null
    try { $org = Invoke-WithRetry { Get-MgOrganization -Property Id, DisplayName, VerifiedDomains -ErrorAction Stop | Select-Object -First 1 } } catch {
        Write-AppLog -Level Warning -Category Graph -Message "Could not read organization: $(Get-GraphErrorSummary $_)"
    }
    $admin = "$($ctx.Account)"
    if (-not $admin) { $admin = "$(Get-SharedValue 'TokenAdmin')" }
    if (-not $admin) { $admin = '(unknown)' }
    $have = @(Get-GrantedScope)
    $missing = @($script:RequiredScopes | Where-Object { $_ -notin $have })
    $default = ''
    if ($org -and $org.VerifiedDomains) { $default = ($org.VerifiedDomains | Where-Object IsDefault | Select-Object -First 1).Name }
    [pscustomobject]@{
        TenantName    = if ($org) { $org.DisplayName } else { '(unavailable)' }
        TenantId      = if ($org) { $org.Id } else { $ctx.TenantId }
        DefaultDomain = $default
        Admin         = $admin
        AuthType      = "$($ctx.AuthType)"
        Scopes        = $have
        MissingScopes = $missing
        CanReadPolicy = ($script:PolicyReadScope -in $have) -or ('Policy.Read.AuthenticationMethod' -in $have)
        CanWritePolicy = ($script:PolicyWriteScope -in $have)
    }
}

function Disconnect-TapGraph {
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    foreach ($k in 'RefreshToken', 'TokenExpiresUtc', 'TokenTenant', 'TokenClientId', 'TokenScopes', 'TokenAdmin', 'TokenGrantedScopes', 'AuthMethod') { Clear-SharedValue $k }
    Clear-LogSecrets
    Write-AppLog -Category Auth -Message 'Signed out; session state cleared.'
}

# ----------------------------------------------------------------- policy
function Get-TapPolicy {
    <# Reads the tenant's Temporary Access Pass method configuration. Never throws: returns Status 'Unknown' when it cannot be read. #>
    Initialize-TapGraphModule
    try {
        $p = Invoke-WithRetry { Invoke-MgGraphRequest -Method GET -OutputType PSObject -ErrorAction Stop `
                -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/TemporaryAccessPass' }
        $targets = @($p.includeTargets | ForEach-Object { $_.id })
        [pscustomobject]@{
            Status = if ($p.state -eq 'enabled') { 'Enabled' } else { 'Disabled' }
            IsUsableOnce = [bool]$p.isUsableOnce
            MinLifetime = [int]$p.minimumLifetimeInMinutes
            MaxLifetime = [int]$p.maximumLifetimeInMinutes
            DefaultLifetime = [int]$p.defaultLifetimeInMinutes
            DefaultLength = [int]$p.defaultLength
            AllUsers = ($targets -contains 'all_users')
            TargetNote = if ($targets -contains 'all_users') { 'All users' } else { "$($targets.Count) group target(s)" }
            Detail = ''
        }
    }
    catch {
        $s = Get-GraphErrorSummary $_
        Write-AppLog -Level Warning -Category Policy -Message "TAP policy not readable: $s"
        [pscustomobject]@{ Status = 'Unknown'; IsUsableOnce = $false; MinLifetime = 0; MaxLifetime = 0; DefaultLifetime = 0; DefaultLength = 0
            AllUsers = $true; TargetNote = 'Unknown'; Detail = "Policy could not be read ($s). Sign in with $script:PolicyReadScope to enable policy checks." }
    }
}

function Set-TapPolicyLength {
    <# TAP length is a TENANT-WIDE policy value in Graph; there is no per-pass length. Returns previous length. #>
    param([Parameter(Mandatory)][ValidateRange(8, 48)][int]$Length)
    $uri = 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/TemporaryAccessPass'
    $cur = Invoke-WithRetry { Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject -ErrorAction Stop }
    $old = [int]$cur.defaultLength
    if ($old -ne $Length) {
        $body = @{ '@odata.type' = '#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration'; defaultLength = $Length } | ConvertTo-Json
        Invoke-WithRetry { Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null }
        Write-AppLog -Level Audit -Category Policy -Message "Tenant TAP policy defaultLength changed $old -> $Length"
    }
    $old
}

# ---------------------------------------------------- permissions check
function Test-TapPermission {
    <# Scope check plus a best-effort look at the admin's directory roles. Returns @{ Errors; Warnings; Info } #>
    Initialize-TapGraphModule
    $res = @{ Errors = @(); Warnings = @(); Info = @() }
    $ctx = Get-MgContext
    if (-not $ctx) { $res.Errors += 'Not signed in.'; return $res }
    $missing = @($script:RequiredScopes | Where-Object { $_ -notin @(Get-GrantedScope) })
    if ($missing) { $res.Errors += "Missing Graph permission(s): $($missing -join ', '). Sign out and sign in again, granting consent." }
    try {
        $roles = @(Invoke-WithRetry { Invoke-MgGraphRequest -Method GET -OutputType PSObject -ErrorAction Stop `
                -Uri 'https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.directoryRole?$select=displayName' }).value.displayName
        $ok = $roles | Where-Object { $_ -in 'Global Administrator', 'Privileged Authentication Administrator', 'Authentication Administrator' }
        if ($ok) { $res.Info += "Admin directory role(s): $($ok -join ', ')" }
        else { $res.Warnings += 'No active Authentication Administrator / Privileged Authentication Administrator / Global Administrator role detected (PIM-eligible roles must be activated; GDAP roles may not show here). TAP creation will fail without one.' }
    }
    catch { $res.Warnings += 'Could not read the signed-in admin''s directory roles; role requirement not verified.' }
    $res
}

# ------------------------------------------------------------ user lookup
function ConvertTo-ODataString { param([string]$Value) $Value.Replace("'", "''") }

function Find-TapGroup {
    param([Parameter(Mandatory)][string]$SearchText)
    Initialize-TapGraphModule
    $t = $SearchText -replace '["\\]', ''
    @(Invoke-WithRetry { Get-MgGroup -Search "`"displayName:$t`"" -ConsistencyLevel eventual -Top 25 -Property Id, DisplayName -ErrorAction Stop } |
        Sort-Object DisplayName | ForEach-Object { [pscustomobject]@{ Id = $_.Id; DisplayName = $_.DisplayName } })
}

function Get-TapUserLookup {
    [CmdletBinding()]
    param(
        [string]$SearchText, [string]$Department, [string]$JobTitle, [string]$GroupId,
        [int]$MaxResults = 500, [bool]$EnabledOnly = $true
    )
    Initialize-TapGraphModule
    $props = 'id', 'displayName', 'userPrincipalName', 'accountEnabled', 'department', 'jobTitle', 'userType'
    if ($GroupId) {
        $raw = Invoke-WithRetry { Get-MgGroupTransitiveMemberAsUser -GroupId $GroupId -Property $props -All -ConsistencyLevel eventual -ErrorAction Stop }
        $q = $raw | Where-Object { $_.UserPrincipalName }
        if ($SearchText) { $q = $q | Where-Object { $_.DisplayName -like "*$SearchText*" -or $_.UserPrincipalName -like "*$SearchText*" } }
        if ($Department) { $q = $q | Where-Object { $_.Department -eq $Department } }
        if ($JobTitle)   { $q = $q | Where-Object { $_.JobTitle -eq $JobTitle } }
        if ($EnabledOnly){ $q = $q | Where-Object { $_.AccountEnabled } }
    }
    else {
        $f = [System.Collections.Generic.List[string]]::new()
        $f.Add("userType eq 'Member'")
        if ($EnabledOnly) { $f.Add('accountEnabled eq true') }
        if ($Department)  { $f.Add("department eq '$(ConvertTo-ODataString $Department)'") }
        if ($JobTitle)    { $f.Add("jobTitle eq '$(ConvertTo-ODataString $JobTitle)'") }
        $gp = @{ Filter = ($f -join ' and '); Property = $props; All = $true; ConsistencyLevel = 'eventual'; CountVariable = 'cnt'; ErrorAction = 'Stop' }
        if ($SearchText) {
            $t = $SearchText -replace '["\\]', ''
            $gp.Search = "`"displayName:$t`" OR `"userPrincipalName:$t`" OR `"mail:$t`""
        }
        $q = Invoke-WithRetry { Get-MgUser @gp }
    }
    @($q | Select-Object -First $MaxResults | ForEach-Object {
        [pscustomobject]@{
            Id = $_.Id; UserPrincipalName = $_.UserPrincipalName; DisplayName = $_.DisplayName
            Department = $_.Department; JobTitle = $_.JobTitle; AccountEnabled = [bool]$_.AccountEnabled; UserType = $_.UserType
        }
    })
}

# -------------------------------------------------------- user validation
function Test-TapUser {
    <# Verifies a single user: exists, enabled, member (not guest). Optionally notes an existing TAP. #>
    param([Parameter(Mandatory)][string]$Identity, [bool]$CheckExistingTap = $true)
    Initialize-TapGraphModule
    $r = [pscustomobject]@{ Id = ''; UserPrincipalName = $Identity; DisplayName = ''; Status = 'Failed'; Detail = ''; ExistingTap = $false }
    try {
        $u = Invoke-WithRetry { Get-MgUser -UserId $Identity -Property id, displayName, userPrincipalName, accountEnabled, userType -ErrorAction Stop }
    }
    catch {
        $code = Get-ErrorStatusCode $_
        $r.Detail = switch ($code) {
            404 { 'User not found in this tenant' }
            403 { 'Access denied reading user (check User.Read.All consent)' }
            default { "Lookup failed: $(Get-GraphErrorSummary $_)" }
        }
        return $r
    }
    $r.Id = $u.Id; $r.UserPrincipalName = $u.UserPrincipalName; $r.DisplayName = $u.DisplayName
    if (-not $u.AccountEnabled) { $r.Detail = 'Account is disabled'; return $r }
    if ($u.UserType -eq 'Guest') { $r.Detail = 'Guest account - TAP is not supported for guests'; return $r }
    $r.Status = 'Valid'; $r.Detail = 'OK'
    if ($CheckExistingTap) {
        try {
            $ex = @(Invoke-WithRetry { Get-MgUserAuthenticationTemporaryAccessPassMethod -UserId $u.Id -ErrorAction Stop })
            $live = @($ex | Where-Object { $_.MethodUsabilityReason -notin 'Expired', 'OneTimeUsed' })   # expired / used passes are listed but harmless
            if ($live.Count -gt 0) { $r.ExistingTap = $true; $r.Status = 'Warning'; $r.Detail = 'User already has a TAP - creating a new one will replace it' }
        }
        catch { if ((Get-ErrorStatusCode $_) -eq 403) { $r.Status = 'Warning'; $r.Detail = 'OK, but could not check for an existing TAP (403)' } }
    }
    $r
}

# ---------------------------------------------------------- TAP creation
function Get-FriendlyTapError {
    param([Parameter(Mandatory)]$ErrorRecord)
    $code = Get-ErrorStatusCode $ErrorRecord
    $raw = Get-GraphErrorSummary $ErrorRecord
    $hint = switch ($code) {
        403 { 'Access denied: the signed-in admin needs Authentication Administrator (or Privileged Authentication Administrator for admin users).' }
        404 { 'User not found.' }
        429 { 'Throttled by Microsoft Graph and retries were exhausted.' }
        401 { 'Session expired or token rejected - sign in again.' }
        400 { if ($raw -match '(?i)policy|not enabled|disabled|scope|target') { 'TAP is not enabled for this user in the Authentication methods policy.' } else { 'Request rejected by Graph.' } }
        default { 'Unexpected Graph error.' }
    }
    [pscustomobject]@{ Status = $code; Message = "$hint [$raw]" }
}

function New-TapForUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$UserId,
        [Parameter(Mandatory)][int]$LifetimeMinutes,
        [bool]$OneTime = $false,
        [Nullable[datetime]]$StartUtc,
        $Cancel
    )
    Initialize-TapGraphModule
    Update-TapGraphToken
    $body = @{ lifetimeInMinutes = $LifetimeMinutes; isUsableOnce = $OneTime }
    if ($StartUtc) { $body.startDateTime = ([datetime]$StartUtc).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'") }
    $resp = Invoke-WithRetry -Cancel $Cancel { New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $UserId -BodyParameter $body -ErrorAction Stop }

    $plain = [string]$resp.TemporaryAccessPass
    $secure = ConvertTo-SecureString $plain -AsPlainText -Force
    $len = $plain.Length
    Register-LogSecret $plain          # from now on, any log line containing it is redacted
    $plain = $null; try { $resp.TemporaryAccessPass = $null } catch { }
    $start = if ($resp.StartDateTime) { ([datetime]$resp.StartDateTime).ToUniversalTime() } else { [datetime]::UtcNow }
    $mins = if ($resp.LifetimeInMinutes) { [int]$resp.LifetimeInMinutes } else { $LifetimeMinutes }
    [pscustomobject]@{
        Tap = $secure; TapLength = $len; OneTimeUse = [bool]$resp.IsUsableOnce
        StartUtc = $start; ExpiryUtc = $start.AddMinutes($mins); LifetimeMinutes = $mins
        CreatedUtc = if ($resp.CreatedDateTime) { ([datetime]$resp.CreatedDateTime).ToUniversalTime() } else { [datetime]::UtcNow }
    }
}

# --------------------------------------------------------- batch workers
function Invoke-TapValidationBatch {
    <# Pre-flight (permissions, policy) then per-user checks. Emits: preflight, user, progress. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Users,
        [int]$LifetimeMinutes = 60, [bool]$OneTime = $false, [Nullable[datetime]]$StartUtc,
        [Parameter(Mandatory)][scriptblock]$Emit, $Cancel
    )
    $perm = Test-TapPermission
    $policy = Get-TapPolicy
    $err = [System.Collections.Generic.List[string]]::new(); $warn = [System.Collections.Generic.List[string]]::new()
    $err.AddRange([string[]]$perm.Errors); $warn.AddRange([string[]]$perm.Warnings)
    switch ($policy.Status) {
        'Disabled' { $err.Add('The Temporary Access Pass method is DISABLED in the Authentication methods policy. Enable it in Entra admin centre > Protection > Authentication methods.') }
        'Unknown'  { $warn.Add($policy.Detail) }
        default {
            if ($LifetimeMinutes -lt $policy.MinLifetime -or $LifetimeMinutes -gt $policy.MaxLifetime) {
                $err.Add("Chosen lifetime ($(Format-Lifetime $LifetimeMinutes)) is outside the tenant policy range ($(Format-Lifetime $policy.MinLifetime) - $(Format-Lifetime $policy.MaxLifetime)).") }
            if ($policy.IsUsableOnce -and -not $OneTime) { $warn.Add('Tenant policy forces one-time use; passes will be one-time regardless of the checkbox.') }
            if (-not $policy.AllUsers) { $warn.Add("TAP is targeted to specific groups ($($policy.TargetNote)); users outside them will fail.") }
        }
    }
    if ($StartUtc -and ([datetime]$StartUtc) -lt [datetime]::UtcNow.AddMinutes(1)) { $err.Add('Activation time must be in the future.') }
    & $Emit 'preflight' @{ Errors = $err.ToArray(); Warnings = $warn.ToArray(); Info = $perm.Info; Policy = $policy }
    Write-AppLog -Category Validation -Message ("Pre-flight: {0} error(s), {1} warning(s); policy {2}" -f $err.Count, $warn.Count, $policy.Status)
    if ($err.Count -gt 0) { return @{ Aborted = $true } }

    $total = @($Users).Count; $i = 0; $ok = 0; $bad = 0; $sw = [Diagnostics.Stopwatch]::StartNew()
    foreach ($u in $Users) {
        if ($Cancel -and $Cancel.Cancel) { & $Emit 'cancelled' @{}; break }
        $i++
        try { Update-TapGraphToken; $v = Test-TapUser -Identity $u.UserPrincipalName }
        catch { $v = [pscustomobject]@{ Id = ''; UserPrincipalName = $u.UserPrincipalName; DisplayName = ''; Status = 'Failed'; Detail = "Check failed: $(Get-GraphErrorSummary $_)"; ExistingTap = $false } }
        if ($v.Status -eq 'Failed') { $bad++ } else { $ok++ }
        Write-AppLog -Level $(if ($v.Status -eq 'Failed') { 'Warning' } else { 'Info' }) -Category Validation -Message "$($u.UserPrincipalName): $($v.Status) - $($v.Detail)"
        & $Emit 'user' @{ Input = $u.UserPrincipalName; Result = $v }
        $eta = if ($i -lt $total) { [int](($sw.Elapsed.TotalSeconds / $i) * ($total - $i)) } else { 0 }
        & $Emit 'progress' @{ Done = $i; Total = $total; Success = $ok; Failed = $bad; Current = $u.UserPrincipalName; EtaSeconds = $eta }
    }
    @{ Aborted = $false; Valid = $ok; Failed = $bad }
}

function Invoke-TapGenerationBatch {
    <# Creates TAPs sequentially (Graph write throttling is per-tenant, so no parallelism). Emits: tap, fail, progress, fatal. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Users,
        [Parameter(Mandatory)][int]$LifetimeMinutes, [bool]$OneTime = $false, [Nullable[datetime]]$StartUtc,
        [int]$PolicyLength = 0, [bool]$RestorePolicyLength = $true,
        [Parameter(Mandatory)][scriptblock]$Emit, $Cancel
    )
    $total = @($Users).Count; $i = 0; $ok = 0; $bad = 0; $authFails = 0; $sw = [Diagnostics.Stopwatch]::StartNew()
    $oldLen = $null
    Write-AppLog -Level Audit -Category Generation -Message ("Batch started: {0} user(s), lifetime {1}, one-time {2}, delayed start {3}" -f $total, (Format-Lifetime $LifetimeMinutes), $OneTime, [bool]$StartUtc)
    try {
        if ($PolicyLength -gt 0) {
            $oldLen = Set-TapPolicyLength -Length $PolicyLength
            & $Emit 'info' @{ Message = "Tenant TAP policy length set to $PolicyLength (was $oldLen)." }
        }
        foreach ($u in $Users) {
            if ($Cancel -and $Cancel.Cancel) { & $Emit 'cancelled' @{}; break }
            $i++
            try {
                $t = New-TapForUser -UserId $u.Id -LifetimeMinutes $LifetimeMinutes -OneTime $OneTime -StartUtc $StartUtc -Cancel $Cancel
                $ok++; $authFails = 0
                Write-AppLog -Level Success -Category Generation -Message "$($u.UserPrincipalName): TAP created (length $($t.TapLength), $(Format-Lifetime $t.LifetimeMinutes), one-time $($t.OneTimeUse))"
                & $Emit 'tap' @{ Upn = $u.UserPrincipalName; DisplayName = $u.DisplayName; Tap = $t }
            }
            catch {
                if ($_.Exception.Message -eq 'Cancelled') { & $Emit 'cancelled' @{}; break }
                $bad++
                $fe = Get-FriendlyTapError $_
                if ($fe.Status -in 401, 403) { $authFails++ } else { $authFails = 0 }
                Write-AppLog -Level Error -Category Generation -Message "$($u.UserPrincipalName): FAILED - $($fe.Message)"
                & $Emit 'fail' @{ Upn = $u.UserPrincipalName; DisplayName = $u.DisplayName; Error = $fe.Message }
                if ($authFails -ge 3) {
                    & $Emit 'fatal' @{ Message = 'Three consecutive authorization failures - stopping the batch. Check the admin role / consent.' }
                    break
                }
            }
            $eta = if ($i -lt $total) { [int](($sw.Elapsed.TotalSeconds / $i) * ($total - $i)) } else { 0 }
            & $Emit 'progress' @{ Done = $i; Total = $total; Success = $ok; Failed = $bad; Current = $u.UserPrincipalName; EtaSeconds = $eta }
            Start-Sleep -Milliseconds 150
        }
    }
    finally {
        if ($null -ne $oldLen -and $RestorePolicyLength -and $oldLen -ne $PolicyLength) {
            try { [void](Set-TapPolicyLength -Length $oldLen); & $Emit 'info' @{ Message = "Tenant TAP policy length restored to $oldLen." } }
            catch { & $Emit 'info' @{ Message = "WARNING: could not restore TAP policy length to $oldLen - fix it manually. $(Get-GraphErrorSummary $_)" } }
        }
        Write-AppLog -Level Audit -Category Generation -Message "Batch finished: $ok created, $bad failed of $total"
    }
    @{ Success = $ok; Failed = $bad; Total = $total }
}

Export-ModuleMember -Function *-*
~~~~

---

## `src/UI/UiTypes.cs`

~~~~csharp
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;

namespace MspTap
{
    public class NotifyBase : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;
        protected void Raise(string name)
        {
            PropertyChangedEventHandler h = PropertyChanged;
            if (h != null) h(this, new PropertyChangedEventArgs(name));
        }
        public void RefreshAll() { Raise(""); }
    }

    // A user in the work queue / lookup results.
    public class UserRow : NotifyBase
    {
        bool selected; string status = "Pending"; string detail = ""; string id = ""; string displayName = "";
        public bool Selected { get { return selected; } set { selected = value; Raise("Selected"); } }
        public string UserPrincipalName { get; set; }
        public string DisplayName { get { return displayName; } set { displayName = value; Raise("DisplayName"); } }
        public string Department { get; set; }
        public string JobTitle { get; set; }
        public string Source { get; set; }
        public string Id { get { return id; } set { id = value; Raise("Id"); } }
        public string Status { get { return status; } set { status = value; Raise("Status"); } }
        public string Detail { get { return detail; } set { detail = value; Raise("Detail"); } }
    }

    // A generated (or failed) TAP. The pass itself is held in a SecureString and only
    // materialised as plain text while "Reveal" is on or when copying/exporting.
    public class TapRow : NotifyBase
    {
        const string Mask = "••••••••••";
        SecureString tap; bool reveal; string status = ""; string error = ""; int tapLength;
        public string UserPrincipalName { get; set; }
        public string DisplayName { get; set; }
        public int TapLength { get { return tapLength; } set { tapLength = value; Raise("TapLength"); } }
        public string Lifetime { get; set; }
        public bool OneTimeUse { get; set; }
        public DateTime? StartUtc { get; set; }
        public DateTime? ExpiryUtc { get; set; }
        public DateTime? CreatedUtc { get; set; }
        public string Created { get { return CreatedUtc.HasValue ? CreatedUtc.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") : ""; } }
        public string Status { get { return status; } set { status = value; Raise("Status"); } }
        public string Error { get { return error; } set { error = value; Raise("Error"); } }
        public bool HasTap { get { return tap != null; } }
        public SecureString Tap
        {
            get { return tap; }
            set { if (tap != null) tap.Dispose(); tap = value; Raise("Tap"); Raise("TapDisplay"); Raise("HasTap"); }
        }
        public bool Reveal { get { return reveal; } set { reveal = value; Raise("Reveal"); Raise("TapDisplay"); } }
        public string TapDisplay
        {
            get
            {
                if (tap == null) return Status == "Cleared" ? "(cleared)" : "";
                return reveal ? GetPlain() : Mask;
            }
        }
        public string GetPlain()
        {
            if (tap == null) return "";
            IntPtr p = Marshal.SecureStringToGlobalAllocUnicode(tap);
            try { return Marshal.PtrToStringUni(p); }
            finally { Marshal.ZeroFreeGlobalAllocUnicode(p); }
        }
        public void ClearTap()
        {
            if (tap != null) { tap.Dispose(); tap = null; }
            reveal = false;
            if (status == "Success") Status = "Cleared";
            Raise("Tap"); Raise("TapDisplay"); Raise("HasTap"); Raise("Reveal");
        }
    }
}
~~~~

---

## `src/UI/MainWindow.xaml`

~~~~xml
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="MSP TAP Generator" Width="1240" Height="820" MinWidth="1000" MinHeight="680"
        WindowStartupLocation="CenterScreen" FontFamily="Segoe UI" FontSize="13"
        Background="{DynamicResource Brush.Window}" Foreground="{DynamicResource Brush.Text}"
        UseLayoutRounding="True" SnapsToDevicePixels="True">
  <Window.Resources>

    <!-- ===== text ===== -->
    <Style TargetType="TextBlock"><Setter Property="Foreground" Value="{DynamicResource Brush.Text}"/></Style>
    <Style x:Key="Muted" TargetType="TextBlock"><Setter Property="Foreground" Value="{DynamicResource Brush.Muted}"/><Setter Property="TextWrapping" Value="Wrap"/></Style>
    <Style x:Key="H1" TargetType="TextBlock"><Setter Property="FontSize" Value="20"/><Setter Property="FontWeight" Value="SemiBold"/></Style>
    <Style x:Key="H2" TargetType="TextBlock"><Setter Property="FontSize" Value="14"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Margin" Value="0,0,0,6"/></Style>
    <Style TargetType="Label"><Setter Property="Foreground" Value="{DynamicResource Brush.Muted}"/><Setter Property="Padding" Value="0,6,0,2"/></Style>

    <!-- ===== cards ===== -->
    <Style x:Key="Card" TargetType="Border">
      <Setter Property="Background" Value="{DynamicResource Brush.Surface}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Brush.Border}"/>
      <Setter Property="BorderThickness" Value="1"/><Setter Property="CornerRadius" Value="6"/>
      <Setter Property="Padding" Value="14"/><Setter Property="Margin" Value="0,0,12,12"/>
    </Style>

    <!-- ===== buttons ===== -->
    <Style TargetType="Button">
      <Setter Property="Foreground" Value="{DynamicResource Brush.Text}"/>
      <Setter Property="Background" Value="{DynamicResource Brush.SurfaceAlt}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Brush.Border}"/>
      <Setter Property="Padding" Value="14,6"/><Setter Property="Margin" Value="0,0,8,0"/><Setter Property="MinHeight" Value="30"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" CornerRadius="4" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" TextElement.Foreground="{TemplateBinding Foreground}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="{DynamicResource Brush.Hover}"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.45"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="Primary" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="{DynamicResource Brush.Accent}"/>
      <Setter Property="Foreground" Value="{DynamicResource Brush.AccentText}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Brush.Accent}"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" CornerRadius="4" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" TextElement.Foreground="{TemplateBinding Foreground}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="{DynamicResource Brush.AccentHover}"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.45"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="HeaderButton" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="#22FFFFFF"/><Setter Property="Foreground" Value="White"/><Setter Property="BorderBrush" Value="#55FFFFFF"/>
    </Style>
    <Style TargetType="ToggleButton">
      <Setter Property="Foreground" Value="{DynamicResource Brush.Text}"/><Setter Property="Background" Value="{DynamicResource Brush.SurfaceAlt}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Brush.Border}"/><Setter Property="Padding" Value="14,6"/><Setter Property="Margin" Value="0,0,8,0"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ToggleButton">
            <Border x:Name="bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" CornerRadius="4" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" TextElement.Foreground="{TemplateBinding Foreground}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsChecked" Value="True"><Setter TargetName="bd" Property="Background" Value="{DynamicResource Brush.Selected}"/></Trigger>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="{DynamicResource Brush.Hover}"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- ===== inputs ===== -->
    <Style TargetType="TextBox">
      <Setter Property="Background" Value="{DynamicResource Brush.Input}"/><Setter Property="Foreground" Value="{DynamicResource Brush.Text}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Brush.Border}"/><Setter Property="CaretBrush" Value="{DynamicResource Brush.Text}"/>
      <Setter Property="Padding" Value="6,5"/><Setter Property="MinHeight" Value="30"/><Setter Property="VerticalContentAlignment" Value="Center"/>
    </Style>
    <Style TargetType="PasswordBox">
      <Setter Property="Background" Value="{DynamicResource Brush.Input}"/><Setter Property="Foreground" Value="{DynamicResource Brush.Text}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Brush.Border}"/><Setter Property="Padding" Value="6,5"/><Setter Property="MinHeight" Value="30"/>
    </Style>
    <Style TargetType="CheckBox"><Setter Property="Foreground" Value="{DynamicResource Brush.Text}"/><Setter Property="Margin" Value="0,5,0,5"/><Setter Property="VerticalContentAlignment" Value="Center"/></Style>
    <Style TargetType="RadioButton"><Setter Property="Foreground" Value="{DynamicResource Brush.Text}"/><Setter Property="Margin" Value="0,4,16,4"/></Style>
    <Style TargetType="ProgressBar"><Setter Property="Height" Value="10"/><Setter Property="Foreground" Value="{DynamicResource Brush.Accent}"/><Setter Property="Background" Value="{DynamicResource Brush.SurfaceAlt}"/><Setter Property="BorderBrush" Value="{DynamicResource Brush.Border}"/></Style>
    <Style TargetType="Expander"><Setter Property="Foreground" Value="{DynamicResource Brush.Muted}"/></Style>

    <ControlTemplate x:Key="ComboToggle" TargetType="ToggleButton">
      <Border x:Name="bd" Background="{DynamicResource Brush.Input}" BorderBrush="{DynamicResource Brush.Border}" BorderThickness="1" CornerRadius="3">
        <Path Data="M0,0 L4,4 L8,0" Stroke="{DynamicResource Brush.Muted}" StrokeThickness="1.5" HorizontalAlignment="Right" VerticalAlignment="Center" Margin="0,0,10,0"/>
      </Border>
    </ControlTemplate>
    <Style TargetType="ComboBox">
      <Setter Property="Foreground" Value="{DynamicResource Brush.Text}"/><Setter Property="MinHeight" Value="30"/><Setter Property="Padding" Value="8,4,28,4"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ComboBox">
            <Grid>
              <ToggleButton Template="{StaticResource ComboToggle}" Focusable="False" IsChecked="{Binding IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}" ClickMode="Press"/>
              <ContentPresenter IsHitTestVisible="False" Margin="{TemplateBinding Padding}" VerticalAlignment="Center" HorizontalAlignment="Left"
                                Content="{TemplateBinding SelectionBoxItem}" ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}" TextElement.Foreground="{DynamicResource Brush.Text}"/>
              <TextBox x:Name="PART_EditableTextBox" Visibility="Hidden" Margin="0,0,24,0" Background="Transparent" BorderThickness="0" IsReadOnly="{Binding IsReadOnly, RelativeSource={RelativeSource TemplatedParent}}"/>
              <Popup IsOpen="{TemplateBinding IsDropDownOpen}" Placement="Bottom" AllowsTransparency="True" Focusable="False" PopupAnimation="Fade">
                <Border MinWidth="{Binding ActualWidth, RelativeSource={RelativeSource TemplatedParent}}" MaxHeight="280" Background="{DynamicResource Brush.Surface}" BorderBrush="{DynamicResource Brush.Border}" BorderThickness="1" CornerRadius="3">
                  <ScrollViewer><ItemsPresenter/></ScrollViewer>
                </Border>
              </Popup>
            </Grid>
            <ControlTemplate.Triggers>
              <Trigger Property="IsEditable" Value="True">
                <Setter TargetName="PART_EditableTextBox" Property="Visibility" Value="Visible"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="ComboBoxItem">
      <Setter Property="Foreground" Value="{DynamicResource Brush.Text}"/><Setter Property="Padding" Value="8,5"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ComboBoxItem">
            <Border x:Name="bd" Padding="{TemplateBinding Padding}" Background="Transparent"><ContentPresenter TextElement.Foreground="{DynamicResource Brush.Text}"/></Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="{DynamicResource Brush.Hover}"/></Trigger>
              <Trigger Property="IsSelected" Value="True"><Setter TargetName="bd" Property="Background" Value="{DynamicResource Brush.Selected}"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- ===== tabs ===== -->
    <Style TargetType="TabControl">
      <Setter Property="Background" Value="Transparent"/><Setter Property="BorderThickness" Value="0"/><Setter Property="Padding" Value="0"/>
    </Style>
    <Style TargetType="TabItem">
      <Setter Property="Foreground" Value="{DynamicResource Brush.Muted}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabItem">
            <Border x:Name="bd" Padding="18,10" Margin="0,0,2,0" BorderThickness="0,0,0,3" BorderBrush="Transparent" Background="Transparent">
              <ContentPresenter ContentSource="Header" TextElement.Foreground="{TemplateBinding Foreground}" TextElement.FontWeight="SemiBold"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="bd" Property="BorderBrush" Value="{DynamicResource Brush.Accent}"/>
                <Setter Property="Foreground" Value="{DynamicResource Brush.Text}"/>
              </Trigger>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="{DynamicResource Brush.Hover}"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- ===== data grid ===== -->
    <Style TargetType="DataGrid">
      <Setter Property="Background" Value="{DynamicResource Brush.Surface}"/><Setter Property="Foreground" Value="{DynamicResource Brush.Text}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Brush.Border}"/><Setter Property="RowBackground" Value="{DynamicResource Brush.Surface}"/>
      <Setter Property="AlternatingRowBackground" Value="{DynamicResource Brush.SurfaceAlt}"/>
      <Setter Property="HorizontalGridLinesBrush" Value="{DynamicResource Brush.Border}"/><Setter Property="VerticalGridLinesBrush" Value="Transparent"/>
      <Setter Property="AutoGenerateColumns" Value="False"/><Setter Property="CanUserAddRows" Value="False"/><Setter Property="CanUserDeleteRows" Value="False"/>
      <Setter Property="HeadersVisibility" Value="Column"/><Setter Property="RowHeaderWidth" Value="0"/><Setter Property="SelectionUnit" Value="FullRow"/>
      <Setter Property="GridLinesVisibility" Value="Horizontal"/><Setter Property="MinRowHeight" Value="28"/><Setter Property="IsReadOnly" Value="True"/>
      <Setter Property="EnableRowVirtualization" Value="True"/>
    </Style>
    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="{DynamicResource Brush.SurfaceAlt}"/><Setter Property="Foreground" Value="{DynamicResource Brush.Muted}"/>
      <Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Padding" Value="10,7"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Brush.Border}"/><Setter Property="BorderThickness" Value="0,0,0,1"/>
    </Style>
    <Style TargetType="DataGridRow">
      <Style.Triggers><Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{DynamicResource Brush.Selected}"/></Trigger></Style.Triggers>
    </Style>
    <Style TargetType="DataGridCell">
      <Setter Property="BorderThickness" Value="0"/><Setter Property="Foreground" Value="{DynamicResource Brush.Text}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="DataGridCell">
            <Border Padding="10,4" Background="Transparent"><ContentPresenter VerticalAlignment="Center"/></Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="StatusCell" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{DynamicResource Brush.Text}"/>
      <Style.Triggers>
        <DataTrigger Binding="{Binding Status}" Value="Failed"><Setter Property="Foreground" Value="{DynamicResource Brush.Danger}"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="Valid"><Setter Property="Foreground" Value="{DynamicResource Brush.Success}"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="Success"><Setter Property="Foreground" Value="{DynamicResource Brush.Success}"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="Warning"><Setter Property="Foreground" Value="{DynamicResource Brush.Warning}"/></DataTrigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="Mono" TargetType="TextBlock"><Setter Property="FontFamily" Value="Consolas"/><Setter Property="Foreground" Value="{DynamicResource Brush.Text}"/></Style>
  </Window.Resources>

  <Grid>
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>

    <!-- ===== persistent tenant banner ===== -->
    <Border Grid.Row="0" Background="{DynamicResource Brush.Header}" Padding="18,10">
      <Grid>
        <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
        <StackPanel Grid.Column="0" Margin="0,0,28,0" VerticalAlignment="Center">
          <TextBlock Text="MSP TAP Generator" FontSize="16" FontWeight="SemiBold" Foreground="White"/>
          <TextBlock Text="Windows Autopilot onboarding" FontSize="11" Foreground="#CCFFFFFF"/>
        </StackPanel>
        <StackPanel Grid.Column="1" VerticalAlignment="Center">
          <TextBlock x:Name="HdrCustomer" Text="Not signed in" FontSize="18" FontWeight="SemiBold" Foreground="White" TextTrimming="CharacterEllipsis"/>
          <TextBlock x:Name="HdrDetail" Text="Sign in to a customer tenant to begin" FontSize="12" Foreground="#E6FFFFFF" TextTrimming="CharacterEllipsis"/>
        </StackPanel>
        <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center">
          <Button x:Name="ThemeBtn" Content="Light / Dark" Style="{StaticResource HeaderButton}"/>
          <Button x:Name="SwitchTenantBtn" Content="Switch tenant" Style="{StaticResource HeaderButton}" IsEnabled="False"/>
          <Button x:Name="SignOutBtn" Content="Sign out" Style="{StaticResource HeaderButton}" IsEnabled="False" Margin="0"/>
        </StackPanel>
      </Grid>
    </Border>

    <!-- ===== main tabs ===== -->
    <TabControl x:Name="MainTabs" Grid.Row="1" Margin="18,8,6,0">

      <!-- Dashboard -->
      <TabItem Header="Dashboard">
        <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="0,14,12,0">
          <StackPanel>
            <WrapPanel>
              <Border Style="{StaticResource Card}" Width="360"><StackPanel>
                <TextBlock Text="Tenant" Style="{StaticResource H2}"/><TextBlock x:Name="DashTenant" TextWrapping="Wrap" LineHeight="20"/></StackPanel></Border>
              <Border Style="{StaticResource Card}" Width="360"><StackPanel>
                <TextBlock Text="Graph permissions" Style="{StaticResource H2}"/><TextBlock x:Name="DashScopes" TextWrapping="Wrap" LineHeight="20"/></StackPanel></Border>
              <Border Style="{StaticResource Card}" Width="360"><StackPanel>
                <TextBlock Text="Temporary Access Pass policy" Style="{StaticResource H2}"/><TextBlock x:Name="DashPolicy" TextWrapping="Wrap" LineHeight="20"/>
                <Button x:Name="RefreshPolicyBtn" Content="Refresh policy" Margin="0,10,0,0" HorizontalAlignment="Left"/></StackPanel></Border>
              <Border Style="{StaticResource Card}" Width="360"><StackPanel>
                <TextBlock Text="This session" Style="{StaticResource H2}"/><TextBlock x:Name="DashSession" TextWrapping="Wrap" LineHeight="20"/></StackPanel></Border>
            </WrapPanel>
            <Border Style="{StaticResource Card}"><StackPanel>
              <TextBlock Text="Workflow" Style="{StaticResource H2}"/>
              <TextBlock Style="{StaticResource Muted}" LineHeight="20"
                Text="1. Import Users - load a CSV, an XLSX sheet, or search Entra.    2. Generate TAPs - choose lifetime and options, Validate, then Generate.    3. Results - reveal, copy or export (mask the TAP unless you need it on disk).    TAP values are never written to the log."/>
            </StackPanel></Border>
          </StackPanel>
        </ScrollViewer>
      </TabItem>

      <!-- Import Users -->
      <TabItem Header="Import Users">
        <Grid Margin="0,14,12,0">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
          <TabControl x:Name="ImportTabs" Grid.Row="0">
            <TabItem Header="CSV">
              <Border Style="{StaticResource Card}" Margin="0,8,0,10"><StackPanel>
                <Label Content="CSV file (UserPrincipalName [,DisplayName])" Padding="0,0,0,4"/>
                <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                  <TextBox x:Name="CsvPath" Margin="0,0,8,0"/>
                  <Button x:Name="CsvBrowseBtn" Grid.Column="1" Content="Browse..." Margin="0,0,8,0"/>
                  <Button x:Name="CsvLoadBtn" Grid.Column="2" Content="Add to queue" Style="{StaticResource Primary}" Margin="0"/></Grid>
                <TextBlock x:Name="CsvMsg" Style="{StaticResource Muted}" Margin="0,8,0,0"/></StackPanel></Border>
            </TabItem>
            <TabItem Header="XLSX">
              <Border Style="{StaticResource Card}" Margin="0,8,0,10"><StackPanel>
                <Label Content="Excel workbook" Padding="0,0,0,4"/>
                <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                  <TextBox x:Name="XlsxPath" Margin="0,0,8,0"/><Button x:Name="XlsxBrowseBtn" Grid.Column="1" Content="Browse..." Margin="0"/></Grid>
                <Grid Margin="0,6,0,0"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                  <StackPanel Margin="0,0,10,0"><Label Content="Sheet"/><ComboBox x:Name="XlsxSheet"/></StackPanel>
                  <StackPanel Grid.Column="1" Margin="0,0,10,0"><Label Content="UserPrincipalName column"/><ComboBox x:Name="XlsxUpnCol"/></StackPanel>
                  <StackPanel Grid.Column="2" Margin="0,0,10,0"><Label Content="DisplayName column (optional)"/><ComboBox x:Name="XlsxNameCol"/></StackPanel>
                  <Button x:Name="XlsxLoadBtn" Grid.Column="3" Content="Add to queue" Style="{StaticResource Primary}" VerticalAlignment="Bottom" Margin="0"/></Grid>
                <TextBlock x:Name="XlsxMsg" Style="{StaticResource Muted}" Margin="0,8,0,0"/></StackPanel></Border>
            </TabItem>
            <TabItem Header="Entra lookup">
              <Border Style="{StaticResource Card}" Margin="0,8,0,10"><StackPanel>
                <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="2*"/><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/><ColumnDefinition Width="80"/></Grid.ColumnDefinitions>
                  <StackPanel Margin="0,0,10,0"><Label Content="Search (name, UPN, mail)"/><TextBox x:Name="LkSearch"/></StackPanel>
                  <StackPanel Grid.Column="1" Margin="0,0,10,0"><Label Content="Department (exact)"/><TextBox x:Name="LkDept"/></StackPanel>
                  <StackPanel Grid.Column="2" Margin="0,0,10,0"><Label Content="Job title (exact)"/><TextBox x:Name="LkTitle"/></StackPanel>
                  <StackPanel Grid.Column="3"><Label Content="Max rows"/><TextBox x:Name="LkMax" Text="500"/></StackPanel></Grid>
                <Grid Margin="0,4,0,0"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="2*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                  <StackPanel Margin="0,0,8,0"><Label Content="Group - find by name"/><TextBox x:Name="LkGroupSearch"/></StackPanel>
                  <Button x:Name="LkFindGroupsBtn" Grid.Column="1" Content="Find groups" VerticalAlignment="Bottom" Margin="0,0,10,0"/>
                  <StackPanel Grid.Column="2" Margin="0,0,10,0"><Label Content="Group (members incl. nested)"/><ComboBox x:Name="LkGroup" DisplayMemberPath="DisplayName"/></StackPanel>
                  <CheckBox x:Name="LkEnabledOnly" Grid.Column="3" Content="Enabled accounts only" IsChecked="True" VerticalAlignment="Bottom" Margin="0,0,0,6"/></Grid>
                <StackPanel Orientation="Horizontal" Margin="0,10,0,0">
                  <Button x:Name="LkSearchBtn" Content="Search Entra" Style="{StaticResource Primary}"/>
                  <Button x:Name="LkAddSelBtn" Content="Add selected to queue"/><Button x:Name="LkAddAllBtn" Content="Add all to queue"/>
                  <TextBlock x:Name="LkMsg" Style="{StaticResource Muted}" VerticalAlignment="Center" Margin="8,0,0,0"/></StackPanel>
                <DataGrid x:Name="LkGrid" Height="170" Margin="0,10,0,0" SelectionMode="Extended">
                  <DataGrid.Columns>
                    <DataGridTextColumn Header="User" Binding="{Binding UserPrincipalName}" Width="2*"/>
                    <DataGridTextColumn Header="Display name" Binding="{Binding DisplayName}" Width="1.5*"/>
                    <DataGridTextColumn Header="Department" Binding="{Binding Department}" Width="*"/>
                    <DataGridTextColumn Header="Job title" Binding="{Binding JobTitle}" Width="*"/>
                  </DataGrid.Columns></DataGrid>
              </StackPanel></Border>
            </TabItem>
          </TabControl>

          <DockPanel Grid.Row="1">
            <TextBlock DockPanel.Dock="Top" Text="Work queue" Style="{StaticResource H2}"/>
            <DataGrid x:Name="QueueGrid" IsReadOnly="False" SelectionMode="Extended">
              <DataGrid.Columns>
                <DataGridTemplateColumn Header="" Width="40"><DataGridTemplateColumn.CellTemplate><DataTemplate>
                  <CheckBox IsChecked="{Binding Selected, UpdateSourceTrigger=PropertyChanged}" HorizontalAlignment="Center" VerticalAlignment="Center" Margin="0"/></DataTemplate></DataGridTemplateColumn.CellTemplate></DataGridTemplateColumn>
                <DataGridTextColumn Header="User" Binding="{Binding UserPrincipalName}" IsReadOnly="True" Width="2*"/>
                <DataGridTextColumn Header="Display name" Binding="{Binding DisplayName}" IsReadOnly="True" Width="1.5*"/>
                <DataGridTextColumn Header="Source" Binding="{Binding Source}" IsReadOnly="True" Width="80"/>
                <DataGridTextColumn Header="Status" Binding="{Binding Status}" IsReadOnly="True" Width="90" ElementStyle="{StaticResource StatusCell}"/>
                <DataGridTextColumn Header="Detail" Binding="{Binding Detail}" IsReadOnly="True" Width="2*"/>
              </DataGrid.Columns></DataGrid>
          </DockPanel>
          <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,10,0,10">
            <Button x:Name="SelAllBtn" Content="Tick all"/><Button x:Name="SelNoneBtn" Content="Untick all"/>
            <Button x:Name="RemoveSelBtn" Content="Remove ticked"/><Button x:Name="ClearQueueBtn" Content="Clear queue"/>
            <TextBlock x:Name="QueueCount" Style="{StaticResource Muted}" VerticalAlignment="Center" Margin="8,0,0,0"/></StackPanel>
        </Grid>
      </TabItem>

      <!-- Generate TAPs -->
      <TabItem Header="Generate TAPs">
        <Grid Margin="0,14,12,10">
          <Grid.ColumnDefinitions><ColumnDefinition Width="370"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
          <ScrollViewer VerticalScrollBarVisibility="Auto" Margin="0,0,14,0">
            <Border Style="{StaticResource Card}" Margin="0"><StackPanel>
              <TextBlock Text="TAP options" Style="{StaticResource H2}"/>
              <Label Content="Lifetime"/><ComboBox x:Name="LifetimeCombo" DisplayMemberPath="Label"/>
              <CheckBox x:Name="OneTimeCheck" Content="One-time use" Margin="0,10,0,5"/>
              <Label Content="Password length (8-48)"/>
              <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="40"/></Grid.ColumnDefinitions>
                <Slider x:Name="LengthSlider" Minimum="8" Maximum="48" Value="12" TickFrequency="1" IsSnapToTickEnabled="True" VerticalAlignment="Center"/>
                <TextBlock x:Name="LengthText" Grid.Column="1" Text="12" HorizontalAlignment="Right" FontWeight="SemiBold" VerticalAlignment="Center"/></Grid>
              <CheckBox x:Name="ApplyLengthCheck" Content="Apply this length to the tenant TAP policy" Margin="0,4,0,0"/>
              <CheckBox x:Name="RestoreLengthCheck" Content="Restore the previous length afterwards" IsChecked="True" Margin="18,0,0,0"/>
              <TextBlock x:Name="LengthNote" Style="{StaticResource Muted}" FontSize="11.5"
                Text="Microsoft Graph has no per-pass length: it is a tenant-wide policy value. Leave unticked to use the tenant's current length (shown on the Dashboard)."/>
              <CheckBox x:Name="DelayCheck" Content="Delay activation (local time)" Margin="0,12,0,5"/>
              <TextBox x:Name="StartBox" IsEnabled="False" ToolTip="yyyy-MM-dd HH:mm  (your local time)"/>
              <TextBlock x:Name="StartHint" Style="{StaticResource Muted}" FontSize="11.5" Text="Format: yyyy-MM-dd HH:mm"/>
              <Label Content="Ticket / change reference (written to the audit log)"/><TextBox x:Name="TicketBox" MaxLength="100"/>
              <Border BorderBrush="{DynamicResource Brush.Border}" BorderThickness="0,1,0,0" Margin="0,12,0,12"/>
              <Button x:Name="ValidateBtn" Content="1. Validate selected users" HorizontalAlignment="Stretch" Margin="0,0,0,8"/>
              <Button x:Name="GenerateBtn" Content="2. Generate TAPs" Style="{StaticResource Primary}" HorizontalAlignment="Stretch" Margin="0,0,0,8" IsEnabled="False"/>
              <Button x:Name="CancelBtn" Content="Cancel running operation" HorizontalAlignment="Stretch" Margin="0" IsEnabled="False"/>
            </StackPanel></Border>
          </ScrollViewer>

          <Grid Grid.Column="1">
            <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
            <Border Grid.Row="0" Style="{StaticResource Card}" Margin="0,0,0,10"><TextBlock x:Name="PreflightText" TextWrapping="Wrap" Text="Tick users in the work queue, then Validate."/></Border>
            <DockPanel Grid.Row="1"><TextBlock DockPanel.Dock="Top" x:Name="ReadyTitle" Text="Ready to process" Style="{StaticResource H2}"/>
              <DataGrid x:Name="ReadyGrid">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="User" Binding="{Binding UserPrincipalName}" Width="2*"/>
                  <DataGridTextColumn Header="Display name" Binding="{Binding DisplayName}" Width="1.5*"/>
                  <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="90" ElementStyle="{StaticResource StatusCell}"/>
                  <DataGridTextColumn Header="Detail" Binding="{Binding Detail}" Width="2*"/>
                </DataGrid.Columns></DataGrid></DockPanel>
            <DockPanel Grid.Row="2" Margin="0,10,0,0"><TextBlock DockPanel.Dock="Top" x:Name="FailedTitle" Text="Validation failures" Style="{StaticResource H2}"/>
              <DataGrid x:Name="FailedGrid">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="User" Binding="{Binding UserPrincipalName}" Width="2*"/>
                  <DataGridTextColumn Header="Reason" Binding="{Binding Detail}" Width="3*" ElementStyle="{StaticResource StatusCell}"/>
                </DataGrid.Columns></DataGrid></DockPanel>
            <Border Grid.Row="3" Style="{StaticResource Card}" Margin="0,10,0,0"><StackPanel>
              <ProgressBar x:Name="Progress" Minimum="0" Maximum="100" Value="0"/>
              <TextBlock x:Name="ProgressText" Margin="0,8,0,0" FontWeight="SemiBold" Text="Idle"/>
              <TextBlock x:Name="CurrentText" Style="{StaticResource Muted}"/>
              <StackPanel Orientation="Horizontal" Margin="0,10,0,0">
                <Button x:Name="RetryBtn" Content="Retry failures" IsEnabled="False"/>
                <Button x:Name="ExportFailBtn" Content="Export failures" IsEnabled="False"/></StackPanel>
            </StackPanel></Border>
          </Grid>
        </Grid>
      </TabItem>

      <!-- Results -->
      <TabItem Header="Results">
        <Grid Margin="0,14,12,10">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
          <WrapPanel Grid.Row="0" Margin="0,0,0,10">
            <ToggleButton x:Name="RevealToggle" Content="Show TAPs"/>
            <Button x:Name="CopyRowBtn" Content="Copy row"/><Button x:Name="CopySelBtn" Content="Copy selected"/>
            <Button x:Name="ExportBtn" Content="Export XLSX" Style="{StaticResource Primary}"/>
            <Button x:Name="ClearResultsBtn" Content="Clear TAPs from memory"/>
            <CheckBox x:Name="MaskExportCheck" Content="Mask TAP in export" IsChecked="True" Margin="12,0,12,0" VerticalAlignment="Center"/>
            <CheckBox x:Name="EncryptCheck" Content="Password-protect workbook" Margin="0,0,6,0" VerticalAlignment="Center"/>
            <PasswordBox x:Name="XlsxPassword" Width="150" IsEnabled="False" Margin="0,0,12,0"/>
            <CheckBox x:Name="ClearAfterExportCheck" Content="Clear TAPs after an unmasked export" IsChecked="True" VerticalAlignment="Center"/>
          </WrapPanel>
          <DataGrid x:Name="ResultsGrid" Grid.Row="1" SelectionMode="Extended">
            <DataGrid.ContextMenu>
              <ContextMenu><MenuItem x:Name="MiReveal" Header="Show / hide this TAP"/><MenuItem x:Name="MiCopyTap" Header="Copy TAP only"/></ContextMenu></DataGrid.ContextMenu>
            <DataGrid.Columns>
              <DataGridTextColumn Header="User" Binding="{Binding UserPrincipalName}" Width="2*"/>
              <DataGridTextColumn Header="Display Name" Binding="{Binding DisplayName}" Width="1.5*"/>
              <DataGridTextColumn Header="TAP" Binding="{Binding TapDisplay}" Width="1.5*" ElementStyle="{StaticResource Mono}"/>
              <DataGridTextColumn Header="Length" Binding="{Binding TapLength}" Width="70"/>
              <DataGridTextColumn Header="Lifetime" Binding="{Binding Lifetime}" Width="90"/>
              <DataGridTextColumn Header="Created" Binding="{Binding Created}" Width="150"/>
              <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="80" ElementStyle="{StaticResource StatusCell}"/>
              <DataGridTextColumn Header="Error" Binding="{Binding Error}" Width="2*"/>
            </DataGrid.Columns></DataGrid>
          <TextBlock x:Name="ResultsNote" Grid.Row="2" Style="{StaticResource Muted}" Margin="0,8,0,0"
            Text="TAPs are held in encrypted memory (SecureString), masked by default, auto-hidden after a short time, and never logged. Copied values are excluded from clipboard history and cleared automatically."/>
        </Grid>
      </TabItem>

      <!-- Logs -->
      <TabItem Header="Logs">
        <Grid Margin="0,14,12,10">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <WrapPanel Margin="0,0,0,10">
            <ComboBox x:Name="LogLevel" Width="120" Margin="0,0,8,0"/><ComboBox x:Name="LogCategory" Width="140" Margin="0,0,8,0"/>
            <TextBox x:Name="LogSearch" Width="240" Margin="0,0,8,0" ToolTip="Filter text (press Enter)"/>
            <Button x:Name="LogRefreshBtn" Content="Refresh"/><Button x:Name="LogFolderBtn" Content="Open log folder"/>
            <TextBlock x:Name="LogCount" Style="{StaticResource Muted}" VerticalAlignment="Center"/></WrapPanel>
          <DataGrid x:Name="LogGrid" Grid.Row="1">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Time" Binding="{Binding Time}" Width="150"/>
              <DataGridTextColumn Header="Level" Binding="{Binding Level}" Width="80"/>
              <DataGridTextColumn Header="Category" Binding="{Binding Category}" Width="100"/>
              <DataGridTextColumn Header="Tenant" Binding="{Binding Tenant}" Width="140"/>
              <DataGridTextColumn Header="Admin" Binding="{Binding Admin}" Width="180"/>
              <DataGridTextColumn Header="Ticket" Binding="{Binding Ticket}" Width="110"/>
              <DataGridTextColumn Header="Message" Binding="{Binding Message}" Width="*"/>
            </DataGrid.Columns></DataGrid>
        </Grid>
      </TabItem>
    </TabControl>

    <!-- ===== sign-in screen (covers the tabs until connected) ===== -->
    <Border x:Name="LoginPanel" Grid.Row="1" Background="{DynamicResource Brush.Window}" Panel.ZIndex="10">
      <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
        <Border Style="{StaticResource Card}" Width="560" Margin="20,30,20,30" Padding="26" HorizontalAlignment="Center">
          <StackPanel>
            <TextBlock Text="Sign in to a customer tenant" Style="{StaticResource H1}"/>
            <TextBlock Style="{StaticResource Muted}" Margin="0,4,0,8" Text="Nothing is stored: no passwords, tokens or refresh tokens are written to disk."/>
            <Label Content="Saved customer"/><ComboBox x:Name="ProfileCombo" DisplayMemberPath="CustomerName"/>
            <Label Content="Customer name"/><TextBox x:Name="CustomerBox"/>
            <Label Content="Tenant ID (GUID) or domain, e.g. contoso.onmicrosoft.com"/><TextBox x:Name="TenantBox"/>
            <StackPanel Orientation="Horizontal" Margin="0,12,0,0">
              <RadioButton x:Name="MethodInteractive" Content="Interactive (browser)" IsChecked="True"/>
              <RadioButton x:Name="MethodDevice" Content="Device code"/></StackPanel>
            <CheckBox x:Name="PolicyReadCheck" Content="Also request Policy.Read.All (enables TAP policy checks)" IsChecked="True"/>
            <CheckBox x:Name="PolicyWriteCheck" Content="Also request Policy.ReadWrite.AuthenticationMethod (only to change TAP length)"/>
            <Expander Header="Advanced" Margin="0,6,0,0"><StackPanel><Label Content="App (client) ID - blank = Microsoft Graph Command Line Tools"/><TextBox x:Name="ClientIdBox"/></StackPanel></Expander>
            <Border x:Name="DevicePanel" Visibility="Collapsed" Margin="0,14,0,0" Padding="14" CornerRadius="6" Background="{DynamicResource Brush.SurfaceAlt}" BorderBrush="{DynamicResource Brush.Accent}" BorderThickness="1">
              <StackPanel>
                <TextBlock Text="Open the page below and enter this code:" Style="{StaticResource Muted}"/>
                <TextBlock x:Name="DeviceCodeText" FontFamily="Consolas" FontSize="30" FontWeight="Bold" Margin="0,6,0,2"/>
                <TextBlock x:Name="DeviceUriText" Foreground="{DynamicResource Brush.Accent}"/>
                <StackPanel Orientation="Horizontal" Margin="0,10,0,0"><Button x:Name="CopyCodeBtn" Content="Copy code"/><Button x:Name="OpenUriBtn" Content="Open page" Margin="0"/></StackPanel>
              </StackPanel></Border>
            <StackPanel Orientation="Horizontal" Margin="0,18,0,0">
              <Button x:Name="SignInBtn" Content="Sign in" Style="{StaticResource Primary}" MinWidth="110"/>
              <Button x:Name="CancelSignInBtn" Content="Cancel" IsEnabled="False"/>
              <Button x:Name="SaveProfileBtn" Content="Save customer"/><Button x:Name="DeleteProfileBtn" Content="Delete saved" Margin="0"/></StackPanel>
            <TextBlock x:Name="LoginStatus" Margin="0,12,0,0" TextWrapping="Wrap" Style="{StaticResource Muted}"/>
          </StackPanel></Border>
      </ScrollViewer>
    </Border>

    <!-- ===== status bar ===== -->
    <Border Grid.Row="2" Background="{DynamicResource Brush.Surface}" BorderBrush="{DynamicResource Brush.Border}" BorderThickness="0,1,0,0" Padding="18,6">
      <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="200"/></Grid.ColumnDefinitions>
        <TextBlock x:Name="StatusText" Text="Ready" Style="{StaticResource Muted}" TextWrapping="NoWrap" TextTrimming="CharacterEllipsis"/>
        <ProgressBar x:Name="BusyBar" Grid.Column="1" IsIndeterminate="True" Visibility="Collapsed" Height="6" VerticalAlignment="Center"/></Grid>
    </Border>
  </Grid>
</Window>
~~~~

---

## `src/UI/Theme.Dark.xaml`

~~~~xml
<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
  <SolidColorBrush x:Key="Brush.Window" Color="#1B1B1F"/>
  <SolidColorBrush x:Key="Brush.Surface" Color="#26262B"/>
  <SolidColorBrush x:Key="Brush.SurfaceAlt" Color="#2F2F36"/>
  <SolidColorBrush x:Key="Brush.Border" Color="#43434C"/>
  <SolidColorBrush x:Key="Brush.Text" Color="#F3F3F5"/>
  <SolidColorBrush x:Key="Brush.Muted" Color="#A9A9B3"/>
  <SolidColorBrush x:Key="Brush.Accent" Color="#479EF5"/>
  <SolidColorBrush x:Key="Brush.AccentHover" Color="#6BB2F7"/>
  <SolidColorBrush x:Key="Brush.AccentText" Color="#0B0B0D"/>
  <SolidColorBrush x:Key="Brush.Success" Color="#6CCB5F"/>
  <SolidColorBrush x:Key="Brush.Danger" Color="#F1707B"/>
  <SolidColorBrush x:Key="Brush.Warning" Color="#F2B84B"/>
  <SolidColorBrush x:Key="Brush.Input" Color="#1F1F24"/>
  <SolidColorBrush x:Key="Brush.Hover" Color="#38383F"/>
  <SolidColorBrush x:Key="Brush.Selected" Color="#1E4A78"/>
  <SolidColorBrush x:Key="Brush.Header" Color="#0F2D4A"/>
</ResourceDictionary>
~~~~

---

## `src/UI/Theme.Light.xaml`

~~~~xml
<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
  <SolidColorBrush x:Key="Brush.Window" Color="#F3F2F1"/>
  <SolidColorBrush x:Key="Brush.Surface" Color="#FFFFFF"/>
  <SolidColorBrush x:Key="Brush.SurfaceAlt" Color="#FAF9F8"/>
  <SolidColorBrush x:Key="Brush.Border" Color="#D2D0CE"/>
  <SolidColorBrush x:Key="Brush.Text" Color="#201F1E"/>
  <SolidColorBrush x:Key="Brush.Muted" Color="#605E5C"/>
  <SolidColorBrush x:Key="Brush.Accent" Color="#0F6CBD"/>
  <SolidColorBrush x:Key="Brush.AccentHover" Color="#115EA3"/>
  <SolidColorBrush x:Key="Brush.AccentText" Color="#FFFFFF"/>
  <SolidColorBrush x:Key="Brush.Success" Color="#107C10"/>
  <SolidColorBrush x:Key="Brush.Danger" Color="#C50F1F"/>
  <SolidColorBrush x:Key="Brush.Warning" Color="#BC4B09"/>
  <SolidColorBrush x:Key="Brush.Input" Color="#FFFFFF"/>
  <SolidColorBrush x:Key="Brush.Hover" Color="#EDEBE9"/>
  <SolidColorBrush x:Key="Brush.Selected" Color="#CFE4FA"/>
  <SolidColorBrush x:Key="Brush.Header" Color="#0F6CBD"/>
</ResourceDictionary>
~~~~

---

## `src/UI/App.UI.ps1`

~~~~powershell
# App.UI.ps1 - WPF code-behind. Dot-sourced by Start-MspTapGenerator.ps1 (which has already imported the modules
# and loaded UiTypes.cs). All state lives in $script: variables so event handlers can reach it.

$script:UiDir   = $PSScriptRoot
$script:Pool    = $null
$script:PoolHandle = $null
$script:Tasks   = [System.Collections.Generic.List[hashtable]]::new()
$script:Tick    = 0
$script:Pumping = $false

$script:S = @{
    Identity = $null; CustomerName = ''; Policy = $null; Busy = $false; Cancel = $null
    ValidatedKey = $null; ValidationAborted = $false; Created = 0; Inline = $false
    Theme = 'Dark'; ClipHash = $null; ClipDeadline = $null; HideDeadline = $null; LastOptions = $null
}
$script:Users      = [System.Collections.ObjectModel.ObservableCollection[MspTap.UserRow]]::new()
$script:Ready      = [System.Collections.ObjectModel.ObservableCollection[MspTap.UserRow]]::new()
$script:FailedV    = [System.Collections.ObjectModel.ObservableCollection[MspTap.UserRow]]::new()
$script:Lookup     = [System.Collections.ObjectModel.ObservableCollection[MspTap.UserRow]]::new()
$script:Results    = [System.Collections.ObjectModel.ObservableCollection[MspTap.TapRow]]::new()
$script:UserIndex  = @{}
$script:UI         = @{}

# ================================================================ helpers
function Show-Msg {
    param([string]$Text, [string]$Title = 'MSP TAP Generator', [string]$Buttons = 'OK', [string]$Icon = 'Information')
    [System.Windows.MessageBox]::Show($script:Window, $Text, $Title, $Buttons, $Icon)
}
function Set-Status { param([string]$Text) $script:UI.StatusText.Text = $Text }
function Get-Brush { param([string]$Key) $script:Window.FindResource($Key) }

function Set-Theme {
    param([ValidateSet('Dark', 'Light')][string]$Name)
    $dict = [System.Windows.Markup.XamlReader]::Load([System.Xml.XmlReader]::Create((Join-Path $script:UiDir "Theme.$Name.xaml")))
    $script:Window.Resources.MergedDictionaries.Clear()
    $script:Window.Resources.MergedDictionaries.Add($dict)
    $script:S.Theme = $Name
}
function Get-SystemTheme {
    try {
        $v = Get-ItemPropertyValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name AppsUseLightTheme -ErrorAction Stop
        if ($v -eq 0) { 'Dark' } else { 'Light' }
    } catch { 'Dark' }
}

function Set-Busy {
    param([bool]$Busy, [string]$Text = '')
    $script:S.Busy = $Busy
    $UI = $script:UI
    $UI.BusyBar.Visibility = if ($Busy) { 'Visible' } else { 'Collapsed' }
    foreach ($n in 'ValidateBtn', 'LkSearchBtn', 'LkFindGroupsBtn', 'RefreshPolicyBtn', 'SwitchTenantBtn', 'SignOutBtn') { $UI[$n].IsEnabled = (-not $Busy) -and ($null -ne $script:S.Identity) }
    $UI.CancelBtn.IsEnabled = $Busy
    $UI.GenerateBtn.IsEnabled = (-not $Busy) -and $script:Ready.Count -gt 0 -and $null -ne $script:S.ValidatedKey
    $UI.RetryBtn.IsEnabled = (-not $Busy) -and (@($script:Results | Where-Object Status -eq 'Failed').Count -gt 0)
    $UI.ExportFailBtn.IsEnabled = (-not $Busy) -and ($script:FailedV.Count + @($script:Results | Where-Object Status -eq 'Failed').Count) -gt 0
    if ($Text) { Set-Status $Text } elseif (-not $Busy) { Set-Status 'Ready' }
}

function Rebuild-UserIndex {
    $script:UserIndex = @{}
    foreach ($u in $script:Users) { $script:UserIndex[$u.UserPrincipalName.ToLowerInvariant()] = $u }
}
function Reset-Validation {
    $script:S.ValidatedKey = $null
    $script:Ready.Clear(); $script:FailedV.Clear()
    $script:UI.GenerateBtn.IsEnabled = $false
}

# ============================================================ task runner
function Initialize-WorkerPool {
    if ($script:Pool) { return }
    $iss = [initialsessionstate]::CreateDefault2()
    $iss.ExecutionPolicy = 'Bypass'
    $iss.ImportPSModule([string[]]$script:ModulePaths)
    $script:Pool = [runspacefactory]::CreateRunspacePool(1, 2, $iss, $Host)
    $script:Pool.ApartmentState = 'MTA'
    $script:Pool.ThreadOptions = 'ReuseThread'
    $script:PoolHandle = $script:Pool.BeginOpen($null, $null)    # non-blocking warm-up
}

function Confirm-WorkerPool {
    try {
        Initialize-WorkerPool
        if ($script:PoolHandle) { $script:Pool.EndOpen($script:PoolHandle); $script:PoolHandle = $null }
        $true
    }
    catch {
        Write-AppLog -Level Warning -Category App -Message "Worker pool unavailable ($($_.Exception.Message)); using inline compatibility mode."
        $false
    }
}

$script:WorkerScript = {
    param($Command, $Params, $Queue, $Cancel, $LogCtx)
    $ErrorActionPreference = 'Stop'
    try {
        Set-LogContext -Session $LogCtx.Session -Tenant $LogCtx.Tenant -TenantId $LogCtx.TenantId -Admin $LogCtx.Admin -Ticket $LogCtx.Ticket
        $emit = { param($t, $d) $Queue.Enqueue([pscustomobject]@{ Type = $t; Data = $d }) }.GetNewClosure()
        $p = @{} + $Params
        $cmd = Get-Command $Command
        if ($cmd.Parameters.ContainsKey('Emit'))   { $p.Emit = $emit }
        if ($cmd.Parameters.ContainsKey('Cancel')) { $p.Cancel = $Cancel }
        $res = @(& $Command @p)
        $Queue.Enqueue([pscustomobject]@{ Type = '__done'; Data = $res })
    }
    catch {
        $msg = try { Get-GraphErrorSummary $_ } catch { $_.Exception.Message }
        $Queue.Enqueue([pscustomobject]@{ Type = '__error'; Data = $msg })
    }
}

function Get-LogContextArgs { $c = Get-LogContext; @{ Session = $c.Session; Tenant = $c.Tenant; TenantId = $c.TenantId; Admin = $c.Admin; Ticket = $c.Ticket } }

function Start-AppTask {
    <# Runs a module command in the worker pool (or inline in compatibility mode). Handlers always run on the UI thread. #>
    param(
        [Parameter(Mandatory)][string]$Command, [hashtable]$Params = @{},
        [scriptblock]$OnMessage, [scriptblock]$OnDone, [scriptblock]$OnError,
        [string]$BusyText = 'Working...', [switch]$ForceInline
    )
    $cancel = [hashtable]::Synchronized(@{ Cancel = $false })
    $script:S.Cancel = $cancel
    if (-not $script:S.Inline -and -not $ForceInline -and -not (Confirm-WorkerPool)) { $script:S.Inline = $true }
    Set-Busy $true $BusyText

    if ($script:S.Inline -or $ForceInline) {
        $emit = {
            param($t, $d)
            if ($OnMessage) { & $OnMessage $t $d }
            [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action] {}, [System.Windows.Threading.DispatcherPriority]::Background)
        }.GetNewClosure()
        try {
            $p = @{} + $Params; $cmd = Get-Command $Command
            if ($cmd.Parameters.ContainsKey('Emit'))   { $p.Emit = $emit }
            if ($cmd.Parameters.ContainsKey('Cancel')) { $p.Cancel = $cancel }
            $res = @(& $Command @p)
            Set-Busy $false
            if ($OnDone) { & $OnDone $res }
        }
        catch {
            Set-Busy $false
            $m = Get-GraphErrorSummary $_
            if ($OnError) { & $OnError $m } else { Show-Msg $m 'Error' 'OK' 'Error' }
        }
        return
    }

    $queue = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
    $ps = [powershell]::Create()
    $ps.RunspacePool = $script:Pool
    [void]$ps.AddScript($script:WorkerScript.ToString()).AddArgument($Command).AddArgument($Params).AddArgument($queue).AddArgument($cancel).AddArgument((Get-LogContextArgs))
    $script:Tasks.Add(@{ Ps = $ps; Handle = $ps.BeginInvoke(); Queue = $queue; OnMessage = $OnMessage; OnDone = $OnDone; OnError = $OnError })
}

function Invoke-TaskPump {
    # called every 100 ms on the UI thread. A modal MessageBox inside a handler keeps the dispatcher (and this timer)
    # running, so guard against re-entry or a task's completion handler could run twice.
    if ($script:Pumping) { return }
    $script:Pumping = $true
    try { Invoke-TaskPumpCore } finally { $script:Pumping = $false }
}
function Invoke-TaskPumpCore {
    foreach ($t in @($script:Tasks)) {
        $item = $null; $n = 0; $finished = $false
        while ($n -lt 300 -and $t.Queue.TryDequeue([ref]$item)) {
            $n++
            switch ($item.Type) {
                '__done'  { $finished = $true; Complete-Task $t { Set-Busy $false; if ($t.OnDone) { & $t.OnDone $item.Data } } }
                '__error' { $finished = $true; Complete-Task $t { Set-Busy $false; if ($t.OnError) { & $t.OnError $item.Data } else { Show-Msg $item.Data 'Error' 'OK' 'Error' } } }
                default   { if ($t.OnMessage) { try { & $t.OnMessage $item.Type $item.Data } catch { Write-AppLog -Level Error -Category UI -Message "Handler error: $($_.Exception.Message)" } } }
            }
            if ($finished) { break }
        }
        if (-not $finished -and $t.Handle.IsCompleted -and $t.Queue.IsEmpty) {
            Complete-Task $t { Set-Busy $false; Show-Msg 'The background worker ended unexpectedly. See the Logs tab.' 'Error' 'OK' 'Error' }
        }
    }
}
function Complete-Task {
    param([hashtable]$Task, [scriptblock]$After)
    [void]$script:Tasks.Remove($Task)
    try { [void]$Task.Ps.EndInvoke($Task.Handle) } catch { }
    try { $Task.Ps.Dispose() } catch { }
    & $After
}

# =========================================================== clipboard
function Set-SecureClipboard {
    param([Parameter(Mandatory)][string]$Text)
    $do = [System.Windows.DataObject]::new()
    $do.SetText($Text)
    foreach ($f in 'ExcludeClipboardContentFromMonitorProcessing', 'CanIncludeInClipboardHistory', 'CanUploadToCloudClipboard') {
        $do.SetData($f, [System.IO.MemoryStream]::new([byte[]](0, 0, 0, 0)))
    }
    [System.Windows.Clipboard]::SetDataObject($do, $true)
    $script:S.ClipHash = [Convert]::ToBase64String([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Text)))
    $script:S.ClipDeadline = (Get-Date).AddSeconds([int]$script:Settings.ClipboardClearSecs)
}
function Clear-ClipboardIfOurs {
    try {
        if ($script:S.ClipHash -and [System.Windows.Clipboard]::ContainsText()) {
            $h = [Convert]::ToBase64String([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes([System.Windows.Clipboard]::GetText())))
            if ($h -eq $script:S.ClipHash) { [System.Windows.Clipboard]::Clear() }
        }
    } catch { }
    $script:S.ClipHash = $null; $script:S.ClipDeadline = $null
}

# ============================================================== header
function Update-Header {
    $UI = $script:UI; $id = $script:S.Identity
    if (-not $id) {
        $UI.HdrCustomer.Text = 'Not signed in'; $UI.HdrDetail.Text = 'Sign in to a customer tenant to begin'
        $script:Window.Title = 'MSP TAP Generator'; return
    }
    $name = if ($script:S.CustomerName) { $script:S.CustomerName } else { $id.TenantName }
    $UI.HdrCustomer.Text = "Customer: $name"
    $UI.HdrDetail.Text = "Tenant ID: $($id.TenantId)   |   Admin: $($id.Admin)   |   Directory: $($id.TenantName)"
    $script:Window.Title = "MSP TAP Generator - $name ($($id.TenantId))"
}

function Update-Dashboard {
    $UI = $script:UI; $id = $script:S.Identity; $p = $script:S.Policy
    if (-not $id) { foreach ($n in 'DashTenant', 'DashScopes', 'DashPolicy') { $UI[$n].Text = '-' } }
    else {
        $UI.DashTenant.Text = "Customer: $(if ($script:S.CustomerName) { $script:S.CustomerName } else { $id.TenantName })`nDirectory: $($id.TenantName)`nTenant ID: $($id.TenantId)`nDefault domain: $($id.DefaultDomain)`nSigned in as: $($id.Admin)`nAuth: $($id.AuthType)"
        $miss = if ($id.MissingScopes.Count) { "MISSING: $($id.MissingScopes -join ', ')" } else { 'All required scopes granted' }
        $lines = foreach ($sc in (Get-RequiredScope)) { $m = if ($sc -in $id.Scopes) { [char]0x2714 } else { [char]0x2716 }; "$m $sc" }
        $r1 = if ($id.CanReadPolicy)  { [char]0x2714 } else { [char]0x25CB }
        $r2 = if ($id.CanWritePolicy) { [char]0x2714 } else { [char]0x25CB }
        $UI.DashScopes.Text = (@($lines) -join "`n") + "`n$r1 Policy.Read.All (optional)`n$r2 Policy.ReadWrite.AuthenticationMethod (optional)`n`n$miss"
        if ($p) {
            $UI.DashPolicy.Text = if ($p.Status -eq 'Unknown') { "Status: Unknown`n$($p.Detail)" } else {
                "Status: $($p.Status)`nLifetime: $(Format-Lifetime $p.MinLifetime) - $(Format-Lifetime $p.MaxLifetime) (default $(Format-Lifetime $p.DefaultLifetime))`nOne-time only: $(if ($p.IsUsableOnce) { 'Yes (forced)' } else { 'No (optional)' })`nPass length: $($p.DefaultLength) characters`nTargets: $($p.TargetNote)" }
        } else { $UI.DashPolicy.Text = 'Loading...' }
    }
    $failed = @($script:Results | Where-Object Status -eq 'Failed').Count
    $UI.DashSession.Text = "Users in queue: $($script:Users.Count) (ticked: $(@($script:Users | Where-Object Selected).Count))`nValidated OK: $($script:Ready.Count)   Validation failures: $($script:FailedV.Count)`nTAPs created this session: $($script:S.Created)`nGeneration failures: $failed"
}

function Update-QueueCount {
    $sel = 0; foreach ($u in $script:Users) { if ($u.Selected) { $sel++ } }
    $script:UI.QueueCount.Text = "$($script:Users.Count) users in queue, $sel ticked"
}

# =============================================================== sign in
function Get-SelectedClientId {
    $c = $script:UI.ClientIdBox.Text.Trim()
    if ($c) { $g = [guid]::Empty; if (-not [guid]::TryParse($c, [ref]$g)) { throw 'The client ID must be a GUID.' }; $c } else { $script:Settings.ClientId }
}

function Start-SignIn {
    $UI = $script:UI
    $tenant = $UI.TenantBox.Text.Trim()
    if (-not (Test-TenantIdentifier $tenant)) { $UI.LoginStatus.Text = 'Enter a valid tenant ID (GUID) or domain name.'; return }
    try { $client = Get-SelectedClientId } catch { $UI.LoginStatus.Text = $_.Exception.Message; return }
    $method = if ($UI.MethodDevice.IsChecked) { 'DeviceCode' } else { 'Interactive' }
    $scopes = Get-DesiredScope -PolicyRead ([bool]$UI.PolicyReadCheck.IsChecked) -PolicyWrite ([bool]$UI.PolicyWriteCheck.IsChecked)
    $UI.LoginStatus.Text = if ($method -eq 'Interactive') { 'Complete the sign-in in the browser window...' } else { 'Requesting device code...' }
    $UI.SignInBtn.IsEnabled = $false; $UI.CancelSignInBtn.IsEnabled = $true; $UI.DevicePanel.Visibility = 'Collapsed'

    Start-AppTask -Command 'Connect-TapGraph' -BusyText "Signing in ($method)..." `
        -Params @{ TenantId = $tenant; Method = $method; Scopes = $scopes; ClientId = $client } `
        -OnMessage {
            param($t, $d)
            if ($t -eq 'devicecode') {
                $script:UI.DeviceCodeText.Text = $d.UserCode; $script:UI.DeviceUriText.Text = $d.Uri
                $script:UI.DevicePanel.Visibility = 'Visible'
                $script:UI.LoginStatus.Text = "Waiting for you to finish sign-in (expires in $([int]($d.ExpiresIn / 60)) min)..."
            }
        } `
        -OnDone {
            param($res)
            $script:UI.SignInBtn.IsEnabled = $true; $script:UI.CancelSignInBtn.IsEnabled = $false
            $id = $res | Where-Object { $_ -and $_.PSObject.Properties['TenantId'] } | Select-Object -Last 1
            if (-not $id -or -not (Get-MgContext)) {
                if (-not $script:S.Inline) {
                    $script:S.Inline = $true
                    Write-AppLog -Level Warning -Category Auth -Message 'Graph context not shared with worker runspace - switching to inline compatibility mode.'
                    $script:UI.LoginStatus.Text = 'Compatibility mode enabled - click Sign in again (the window may pause while Graph calls run).'
                } else { $script:UI.LoginStatus.Text = 'Sign-in did not complete.' }
                return
            }
            Complete-SignIn $id
        } `
        -OnError {
            param($m)
            $script:UI.SignInBtn.IsEnabled = $true; $script:UI.CancelSignInBtn.IsEnabled = $false
            $script:UI.DevicePanel.Visibility = 'Collapsed'
            $script:UI.LoginStatus.Text = "Sign-in failed: $m"
            Write-AppLog -Level Error -Category Auth -Message "Sign-in failed: $m"
        }
}

function Complete-SignIn {
    param($Identity)
    $UI = $script:UI
    $typed = $UI.TenantBox.Text.Trim(); $g = [guid]::Empty
    if ([guid]::TryParse($typed, [ref]$g) -and $Identity.TenantId -and ([guid]$Identity.TenantId) -ne $g) {
        Disconnect-TapGraph
        $UI.LoginStatus.Text = "Tenant mismatch: you asked for $typed but signed in to $($Identity.TenantId). Signed out for safety."
        Write-AppLog -Level Error -Category Auth -Message "Tenant mismatch (requested $typed, got $($Identity.TenantId)); signed out."
        return
    }
    $script:S.Identity = $Identity
    $script:S.CustomerName = $UI.CustomerBox.Text.Trim()
    Set-LogContext -Tenant $(if ($script:S.CustomerName) { $script:S.CustomerName } else { $Identity.TenantName }) -TenantId $Identity.TenantId -Admin $Identity.Admin
    Write-AppLog -Level Audit -Category Auth -Message "Signed in. Scopes: $($Identity.Scopes -join ', ')"
    if ($Identity.MissingScopes.Count) { Write-AppLog -Level Warning -Category Auth -Message "Missing scopes: $($Identity.MissingScopes -join ', ')" }
    $UI.LoginPanel.Visibility = 'Collapsed'; $UI.DevicePanel.Visibility = 'Collapsed'; $UI.LoginStatus.Text = ''
    $UI.SwitchTenantBtn.IsEnabled = $true; $UI.SignOutBtn.IsEnabled = $true
    $script:S.Policy = $null
    Update-Header; Update-Dashboard; $UI.MainTabs.SelectedIndex = 0
    if ($Identity.MissingScopes.Count) { Show-Msg "Some required Graph permissions were not granted:`n`n$($Identity.MissingScopes -join "`n")`n`nA customer administrator must consent. TAP creation will fail until then." 'Missing permissions' 'OK' 'Warning' }
    Refresh-Policy
}

function Refresh-Policy {
    Start-AppTask -Command 'Get-TapPolicy' -BusyText 'Reading TAP policy...' -OnDone {
        param($res)
        $p = $res | Select-Object -Last 1
        $script:S.Policy = $p
        $script:UI.OneTimeCheck.IsEnabled = $true
        if ($p.Status -eq 'Enabled') {
            if ($p.IsUsableOnce) { $script:UI.OneTimeCheck.IsChecked = $true; $script:UI.OneTimeCheck.IsEnabled = $false }
            if ($p.DefaultLength -ge 8 -and -not $script:UI.ApplyLengthCheck.IsChecked) { $script:UI.LengthSlider.Value = $p.DefaultLength }
            $script:UI.LengthNote.Text = "Tenant policy currently issues $($p.DefaultLength)-character passes. Microsoft Graph has no per-pass length: tick the box to change the tenant-wide value for this batch (needs the Policy.ReadWrite.AuthenticationMethod permission)."
        }
        Update-Dashboard
    }
}

function Invoke-SignOut {
    $pending = @($script:Results | Where-Object HasTap).Count
    if ($pending -gt 0) {
        $a = Show-Msg "$pending generated TAP(s) are still in memory and will be discarded. Export them first if you need them.`n`nSign out anyway?" 'Discard TAPs?' 'YesNo' 'Warning'
        if ($a -ne 'Yes') { return }
    }
    foreach ($r in $script:Results) { $r.ClearTap() }
    $script:Results.Clear(); $script:Users.Clear(); $script:Ready.Clear(); $script:FailedV.Clear(); $script:Lookup.Clear(); Rebuild-UserIndex
    $script:S.ValidatedKey = $null; $script:S.Created = 0
    Disconnect-TapGraph
    Set-LogContext -Tenant '' -TenantId '' -Admin ''
    $script:S.Identity = $null; $script:S.Policy = $null; $script:S.CustomerName = ''
    $script:UI.LoginPanel.Visibility = 'Visible'
    $script:UI.SwitchTenantBtn.IsEnabled = $false; $script:UI.SignOutBtn.IsEnabled = $false
    $script:UI.PreflightText.Text = 'Tick users in the work queue, then Validate.'
    $script:UI.OneTimeCheck.IsEnabled = $true; $script:UI.OneTimeCheck.IsChecked = $false
    $script:UI.ApplyLengthCheck.IsChecked = $false; $script:UI.LengthSlider.IsEnabled = $false
    $script:UI.TicketBox.Clear(); $script:UI.Progress.Value = 0; $script:UI.ProgressText.Text = 'Idle'; $script:UI.CurrentText.Text = ''
    $script:UI.ReadyTitle.Text = 'Ready to process'; $script:UI.FailedTitle.Text = 'Validation failures'
    Set-LogContext -Ticket ''
    Update-Header; Update-Dashboard; Update-QueueCount; Set-Busy $false
}

function Update-ProfileList {
    $script:UI.ProfileCombo.ItemsSource = @(Get-TenantProfile)
}

# ============================================================ importing
function Add-UsersToQueue {
    param([object[]]$Records, [string]$Source)
    $added = 0; $dupes = 0
    foreach ($r in $Records) {
        $key = $r.UserPrincipalName.ToLowerInvariant()
        if ($script:UserIndex.ContainsKey($key)) { $dupes++; continue }
        $row = [MspTap.UserRow]::new()
        $row.UserPrincipalName = $r.UserPrincipalName; $row.DisplayName = "$($r.DisplayName)"; $row.Source = $Source; $row.Selected = $true
        if ($r.PSObject.Properties['Department']) { $row.Department = $r.Department; $row.JobTitle = $r.JobTitle }
        if ($r.PSObject.Properties['Id'] -and $r.Id) { $row.Id = $r.Id }
        $script:Users.Add($row); $script:UserIndex[$key] = $row; $added++
    }
    if ($added) { Reset-Validation }
    Update-QueueCount; Update-Dashboard
    "$added added, $dupes already in queue"
}

function Add-LookupToQueue {
    param([object[]]$Rows)
    $recs = @($Rows | ForEach-Object { [pscustomobject]@{ UserPrincipalName = $_.UserPrincipalName; DisplayName = $_.DisplayName; Department = $_.Department; JobTitle = $_.JobTitle; Id = $_.Id } })
    $script:UI.LkMsg.Text = Add-UsersToQueue $recs 'Entra'
}

function Format-Skipped {
    param($Skipped)
    if (-not $Skipped -or @($Skipped).Count -eq 0) { return '' }
    $first = @($Skipped | Select-Object -First 3 | ForEach-Object { "row $($_.Row): $($_.Reason)" }) -join '; '
    " Skipped $(@($Skipped).Count) (e.g. $first)."
}

function Select-File {
    param([string]$Filter)
    $d = [Microsoft.Win32.OpenFileDialog]::new(); $d.Filter = $Filter; $d.CheckFileExists = $true
    if ($d.ShowDialog($script:Window)) { $d.FileName }
}

function Update-XlsxColumns {
    $UI = $script:UI
    if (-not $UI.XlsxSheet.SelectedItem) { return }
    try {
        $cols = @(Get-XlsxColumnName -Path $UI.XlsxPath.Text -Sheet $UI.XlsxSheet.SelectedItem)
        $UI.XlsxUpnCol.ItemsSource = $cols
        $UI.XlsxNameCol.ItemsSource = @('(none)') + $cols
        $upn = $cols | Where-Object { $_ -match '^(user ?principal ?name|upn|e-?mail|mail|user ?name)$' } | Select-Object -First 1
        $nm = $cols | Where-Object { $_ -match '^(display ?name|name|full ?name)$' } | Select-Object -First 1
        $UI.XlsxUpnCol.SelectedItem = if ($upn) { $upn } else { $cols | Select-Object -First 1 }
        $UI.XlsxNameCol.SelectedItem = if ($nm) { $nm } else { '(none)' }
    } catch { $UI.XlsxMsg.Text = $_.Exception.Message }
}

function Get-LookupParams {
    $UI = $script:UI; $max = 0
    if (-not [int]::TryParse($UI.LkMax.Text, [ref]$max) -or $max -lt 1) { $max = 500 }
    $max = [Math]::Min($max, 5000)
    $p = @{ SearchText = $UI.LkSearch.Text.Trim(); Department = $UI.LkDept.Text.Trim(); JobTitle = $UI.LkTitle.Text.Trim(); MaxResults = $max; EnabledOnly = [bool]$UI.LkEnabledOnly.IsChecked }
    if ($UI.LkGroup.SelectedItem) { $p.GroupId = $UI.LkGroup.SelectedItem.Id }
    $p
}

# ============================================================ generation
function Get-GenOptions {
    $UI = $script:UI
    $ticket = $UI.TicketBox.Text.Trim()
    if ($ticket.Length -gt 100 -or $ticket -match '[\r\n]') { Show-Msg 'Ticket reference must be one line, 100 characters or less.' 'Options' 'OK' 'Warning'; return $null }
    if (-not $ticket -and $script:Settings.RequireTicket) { Show-Msg 'A ticket / change reference is required (RequireTicket is on in settings.json).' 'Options' 'OK' 'Warning'; return $null }
    Set-LogContext -Ticket $ticket
    $lt = $UI.LifetimeCombo.SelectedItem
    if (-not $lt) { Show-Msg 'Choose a lifetime.' 'Options' 'OK' 'Warning'; return $null }
    $start = $null
    if ($UI.DelayCheck.IsChecked) {
        $dt = [datetime]::MinValue
        if (-not [datetime]::TryParseExact($UI.StartBox.Text.Trim(), 'yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeLocal, [ref]$dt)) {
            Show-Msg 'Activation time must look like 2026-12-01 09:00 (your local time).' 'Options' 'OK' 'Warning'; return $null }
        if ($dt.ToUniversalTime() -lt [datetime]::UtcNow.AddMinutes(1)) { Show-Msg 'Activation time must be in the future.' 'Options' 'OK' 'Warning'; return $null }
        $start = $dt.ToUniversalTime()
    }
    $o = @{
        LifetimeMinutes = [int]$lt.Minutes; OneTime = [bool]$UI.OneTimeCheck.IsChecked; StartUtc = $start
        PolicyLength = if ($UI.ApplyLengthCheck.IsChecked) { [int]$UI.LengthSlider.Value } else { 0 }
        RestorePolicyLength = [bool]$UI.RestoreLengthCheck.IsChecked
    }
    $o.Ticket = $ticket
    $o.Key = "$($o.LifetimeMinutes)|$($o.OneTime)|$($o.StartUtc)"
    $o
}

function Start-Validation {
    $UI = $script:UI
    $sel = @($script:Users | Where-Object Selected)
    if ($sel.Count -eq 0) { Show-Msg 'Tick at least one user in the work queue (Import Users tab).' 'Nothing to validate' 'OK' 'Information'; return }
    $o = Get-GenOptions; if (-not $o) { return }
    Reset-Validation; $script:S.LastOptions = $o
    foreach ($u in $sel) { $u.Status = 'Pending'; $u.Detail = '' }
    $UI.PreflightText.Text = 'Running pre-flight checks...'; $UI.PreflightText.Foreground = Get-Brush 'Brush.Text'
    $UI.Progress.Value = 0; $UI.ProgressText.Text = "Validating 0 / $($sel.Count)"; $UI.CurrentText.Text = ''
    $list = @($sel | ForEach-Object { [pscustomobject]@{ UserPrincipalName = $_.UserPrincipalName; DisplayName = $_.DisplayName } })
    $script:S.ValidationAborted = $false

    Start-AppTask -Command 'Invoke-TapValidationBatch' -BusyText 'Validating users...' `
        -Params @{ Users = $list; LifetimeMinutes = $o.LifetimeMinutes; OneTime = $o.OneTime; StartUtc = $o.StartUtc } `
        -OnMessage {
            param($t, $d)
            switch ($t) {
                'preflight' {
                    $lines = @()
                    foreach ($e in $d.Errors)   { $lines += "$([char]0x2716) $e" }
                    foreach ($w in $d.Warnings) { $lines += "$([char]0x26A0) $w" }
                    foreach ($i in $d.Info)     { $lines += "$([char]0x2714) $i" }
                    if ($d.Errors.Count -eq 0 -and $d.Warnings.Count -eq 0) { $lines += "$([char]0x2714) Permissions and TAP policy look good." }
                    $script:UI.PreflightText.Text = $lines -join "`n"
                    $script:UI.PreflightText.Foreground = Get-Brush $(if ($d.Errors.Count) { 'Brush.Danger' } elseif ($d.Warnings.Count) { 'Brush.Warning' } else { 'Brush.Text' })
                    if ($d.Errors.Count) { $script:S.ValidationAborted = $true }
                    $script:S.Policy = $d.Policy; Update-Dashboard
                }
                'user' {
                    $row = $script:UserIndex[$d.Input.ToLowerInvariant()]
                    if ($row) { $r = $d.Result; $row.Id = $r.Id; if ($r.DisplayName) { $row.DisplayName = $r.DisplayName }; $row.Status = $r.Status; $row.Detail = $r.Detail }
                }
                'progress' {
                    $script:UI.Progress.Value = if ($d.Total) { 100 * $d.Done / $d.Total } else { 0 }
                    $script:UI.ProgressText.Text = "Validating $($d.Done) / $($d.Total)   OK: $($d.Success)   Failed: $($d.Failed)   ETA $([timespan]::FromSeconds($d.EtaSeconds).ToString('mm\:ss'))"
                    $script:UI.CurrentText.Text = "Current: $($d.Current)"
                }
            }
        } `
        -OnDone {
            param($res)
            foreach ($u in @($script:Users | Where-Object Selected)) {
                if ($u.Status -in 'Valid', 'Warning') { $script:Ready.Add($u) } elseif ($u.Status -eq 'Failed') { $script:FailedV.Add($u) }
            }
            $script:UI.ReadyTitle.Text = "Ready to process ($($script:Ready.Count))"; $script:UI.FailedTitle.Text = "Validation failures ($($script:FailedV.Count))"
            if (-not $script:S.ValidationAborted -and $script:Ready.Count -gt 0) { $script:S.ValidatedKey = $script:S.LastOptions.Key }
            $script:UI.ProgressText.Text = if ($script:S.ValidationAborted) { 'Validation stopped: fix the pre-flight errors above.' } else { "Validation complete: $($script:Ready.Count) ready, $($script:FailedV.Count) failed." }
            $script:UI.CurrentText.Text = ''
            Set-Busy $false; Update-Dashboard
        } `
        -OnError { param($m) $script:UI.PreflightText.Text = "$([char]0x2716) Validation failed: $m"; $script:UI.PreflightText.Foreground = Get-Brush 'Brush.Danger' }
}

function Start-Generation {
    param([object[]]$Rows, [bool]$IsRetry = $false)
    $UI = $script:UI
    if (-not $IsRetry) {
        $Rows = @($Rows | Where-Object { $_.Status -in 'Valid', 'Warning' })
        if ($Rows.Count -eq 0) { Show-Msg 'No validated users left to process. Validate again first.' 'Nothing to do' 'OK' 'Information'; return }
    }
    $o = Get-GenOptions; if (-not $o) { return }
    if (-not $IsRetry -and $script:S.ValidatedKey -ne $o.Key) {
        Show-Msg 'The options changed since validation. Please Validate again.' 'Re-validate' 'OK' 'Warning'; return }
    if ($o.PolicyLength -gt 0 -and -not $script:S.Identity.CanWritePolicy) {
        Show-Msg "Changing the tenant TAP length needs the Policy.ReadWrite.AuthenticationMethod permission.`n`nSign out and sign in again with that box ticked, or untick 'Apply this length'." 'Permission needed' 'OK' 'Warning'; return }
    $id = $script:S.Identity
    $name = if ($script:S.CustomerName) { $script:S.CustomerName } else { $id.TenantName }
    $tk = if ($o.Ticket) { $o.Ticket } else { '(none entered)' }
    $text = "Ticket / change: $tk`n`nCreate $($Rows.Count) Temporary Access Pass(es) in:`n`n   $name`n   Tenant ID: $($id.TenantId)`n`nLifetime: $(Format-Lifetime $o.LifetimeMinutes)`nOne-time use: $($o.OneTime)`nActivation: $(if ($o.StartUtc) { ([datetime]$o.StartUtc).ToLocalTime().ToString('yyyy-MM-dd HH:mm') } else { 'immediately' })"
    $existing = @($Rows | Where-Object { $_.Status -eq 'Warning' -and $_.Detail -like '*already has a TAP*' }).Count
    if ($existing) { $text += "`n`n$existing user(s) already have a TAP. The old pass is replaced (deleted) when the new one is created." }
    if ($o.PolicyLength -gt 0) { $text += "`n`nTenant-wide TAP length will be set to $($o.PolicyLength)$(if ($o.RestorePolicyLength) { ' and restored afterwards' } else { ' and NOT restored' })." }
    if ((Show-Msg ($text + "`n`nContinue?") 'Confirm TAP creation' 'YesNo' 'Question') -ne 'Yes') { return }

    $list = @($Rows | ForEach-Object { [pscustomobject]@{ Id = $_.Id; UserPrincipalName = $_.UserPrincipalName; DisplayName = $_.DisplayName } })
    $UI.Progress.Value = 0; $UI.ProgressText.Text = "Creating 0 / $($list.Count)"; $UI.CurrentText.Text = ''
    $script:S.LastOptions = $o

    Start-AppTask -Command 'Invoke-TapGenerationBatch' -BusyText 'Creating TAPs...' `
        -Params @{ Users = $list; LifetimeMinutes = $o.LifetimeMinutes; OneTime = $o.OneTime; StartUtc = $o.StartUtc
                   PolicyLength = $o.PolicyLength; RestorePolicyLength = $o.RestorePolicyLength } `
        -OnMessage {
            param($t, $d)
            switch ($t) {
                'tap' {
                    $row = $script:Results | Where-Object UserPrincipalName -eq $d.Upn | Select-Object -First 1
                    if (-not $row) { $row = [MspTap.TapRow]::new(); $row.UserPrincipalName = $d.Upn; $script:Results.Add($row) }
                    $t2 = $d.Tap
                    $row.DisplayName = $d.DisplayName; $row.TapLength = $t2.TapLength; $row.Lifetime = Format-Lifetime $t2.LifetimeMinutes
                    $row.OneTimeUse = $t2.OneTimeUse; $row.StartUtc = $t2.StartUtc; $row.ExpiryUtc = $t2.ExpiryUtc; $row.CreatedUtc = $t2.CreatedUtc
                    $row.Error = ''; $row.Tap = $t2.Tap; $row.Status = 'Success'
                    $script:S.Created++
                    $u = $script:UserIndex[$d.Upn.ToLowerInvariant()]; if ($u) { $u.Status = 'Success'; $u.Detail = 'TAP created' }
                    $row.RefreshAll()
                }
                'fail' {
                    $row = $script:Results | Where-Object UserPrincipalName -eq $d.Upn | Select-Object -First 1
                    if (-not $row) { $row = [MspTap.TapRow]::new(); $row.UserPrincipalName = $d.Upn; $script:Results.Add($row) }
                    $row.DisplayName = $d.DisplayName; $row.Tap = $null; $row.Status = 'Failed'; $row.Error = $d.Error
                    $u = $script:UserIndex[$d.Upn.ToLowerInvariant()]; if ($u) { $u.Status = 'Failed'; $u.Detail = $d.Error }
                    $row.RefreshAll()
                }
                'progress' {
                    $script:UI.Progress.Value = if ($d.Total) { 100 * $d.Done / $d.Total } else { 0 }
                    $script:UI.ProgressText.Text = "Users: $($d.Total)   Done: $($d.Done)   Success: $($d.Success)   Failed: $($d.Failed)   ETA $([timespan]::FromSeconds($d.EtaSeconds).ToString('mm\:ss'))"
                    $script:UI.CurrentText.Text = "Current: $($d.Current)"
                }
                'info'      { Set-Status $d.Message; $script:UI.CurrentText.Text = $d.Message }
                'fatal'     { Show-Msg $d.Message 'Batch stopped' 'OK' 'Error' }
                'cancelled' { $script:UI.CurrentText.Text = 'Cancelled by user.' }
            }
        } `
        -OnDone {
            param($res)
            $failed = @($script:Results | Where-Object Status -eq 'Failed').Count
            $script:UI.ProgressText.Text = "Finished. $($script:S.Created) created this session, $failed failed."
            # A finished batch must be re-validated before another one, so passes are never created twice by a double click.
            $script:S.ValidatedKey = $null
            Set-Busy $false; Update-Dashboard
            if ($script:Results.Count) { $script:UI.MainTabs.SelectedIndex = 3 }
        } `
        -OnError { param($m) Show-Msg "Generation failed: $m" 'Error' 'OK' 'Error'; Update-Dashboard }
}

# =============================================================== results
function Get-ResultRows { param([switch]$SelectedOnly)
    if ($SelectedOnly) { @($script:UI.ResultsGrid.SelectedItems) } else { @($script:Results) }
}
function Copy-Rows {
    param([object[]]$Rows, [switch]$TapOnly)
    $Rows = @($Rows | Where-Object { $_ })
    if ($Rows.Count -eq 0) { Show-Msg 'Select one or more rows first.' 'Copy' 'OK' 'Information'; return }
    $lines = foreach ($r in $Rows) {
        if ($TapOnly) { $r.GetPlain() }
        else { "{0}`t{1}`t{2}`t{3}`t{4}`t{5}" -f $r.UserPrincipalName, $r.DisplayName, $r.GetPlain(), $r.TapLength, $r.Lifetime, $r.Created }
    }
    try {
        Set-SecureClipboard ($lines -join [Environment]::NewLine)
        Set-Status "Copied $($Rows.Count) row(s). Clipboard clears in $($script:Settings.ClipboardClearSecs)s and is excluded from clipboard history."
        Write-AppLog -Category UI -Message "Copied $($Rows.Count) result row(s) to clipboard (values not logged)."
    } catch { Show-Msg "Clipboard unavailable: $($_.Exception.Message)" 'Copy' 'OK' 'Warning' }
}

function Export-Results {
    $UI = $script:UI
    if ($script:Results.Count -eq 0) { Show-Msg 'Nothing to export yet.' 'Export' 'OK' 'Information'; return }
    $mask = [bool]$UI.MaskExportCheck.IsChecked
    $pw = ''
    if ($UI.EncryptCheck.IsChecked) {
        $pw = [System.Net.NetworkCredential]::new('', $UI.XlsxPassword.SecurePassword).Password
        if ($pw.Length -lt 8) { Show-Msg 'Use a workbook password of at least 8 characters.' 'Export' 'OK' 'Warning'; return }
    }
    if (-not $mask -and -not $pw) {
        $a = Show-Msg "This export will contain TAPs in clear text and is not password-protected.`n`nAnyone who opens the file can sign in as these users until the passes expire.`n`nExport anyway?" 'Unmasked export' 'YesNo' 'Warning'
        if ($a -ne 'Yes') { return }
    }
    $d = [Microsoft.Win32.SaveFileDialog]::new(); $d.Filter = 'Excel workbook (*.xlsx)|*.xlsx'; $d.FileName = Get-TapExportFileName; $d.AddExtension = $true
    if (-not $d.ShowDialog($script:Window)) { return }
    try {
        $rows = foreach ($r in $script:Results) {
            [pscustomobject]@{ UserPrincipalName = $r.UserPrincipalName; DisplayName = $r.DisplayName; Tap = $r.Tap; TapLength = $r.TapLength
                OneTimeUse = $r.OneTimeUse; StartUtc = $r.StartUtc; ExpiryUtc = $r.ExpiryUtc; Status = if ($r.Status -eq 'Failed') { "Failed: $($r.Error)" } else { $r.Status } }
        }
        Export-TapResult -Rows @($rows) -Path $d.FileName -MaskTap:$mask -WorkbookPassword $pw -Reference $UI.TicketBox.Text.Trim()
        $msg = "Exported to:`n$($d.FileName)"
        if (-not $mask -and $UI.ClearAfterExportCheck.IsChecked) {
            foreach ($r in $script:Results) { $r.ClearTap() }
            Clear-LogSecrets; $UI.RevealToggle.IsChecked = $false
            $msg += "`n`nTAP values have been cleared from memory."
        }
        Show-Msg $msg 'Export complete'
    }
    catch { Write-AppLog -Level Error -Category Export -Message "Export failed: $($_.Exception.Message)"; Show-Msg "Export failed: $($_.Exception.Message)" 'Export' 'OK' 'Error' }
    finally { $pw = $null; $UI.XlsxPassword.Clear() }
}

function Export-Failures {
    $rows = @()
    foreach ($u in $script:FailedV) { $rows += [pscustomobject]@{ UserPrincipalName = $u.UserPrincipalName; DisplayName = $u.DisplayName; Stage = 'Validation'; Detail = $u.Detail } }
    foreach ($r in ($script:Results | Where-Object Status -eq 'Failed')) { $rows += [pscustomobject]@{ UserPrincipalName = $r.UserPrincipalName; DisplayName = $r.DisplayName; Stage = 'Generation'; Detail = $r.Error } }
    if ($rows.Count -eq 0) { Show-Msg 'No failures to export.'; return }
    $d = [Microsoft.Win32.SaveFileDialog]::new(); $d.Filter = 'Excel workbook (*.xlsx)|*.xlsx'; $d.FileName = 'TAP_Failures_{0:yyyyMMdd_HHmmss}.xlsx' -f (Get-Date)
    if (-not $d.ShowDialog($script:Window)) { return }
    try { Export-FailureReport -Rows $rows -Path $d.FileName; Show-Msg "Exported $($rows.Count) failure(s) to:`n$($d.FileName)" 'Export complete' }
    catch { Show-Msg "Export failed: $($_.Exception.Message)" 'Export' 'OK' 'Error' }
}

# ================================================================= logs
function Update-LogView {
    $UI = $script:UI
    $rows = @(Read-AppLog -Days 7 -Max 4000)
    $lv = $UI.LogLevel.SelectedItem; $cat = $UI.LogCategory.SelectedItem; $q = $UI.LogSearch.Text.Trim()
    if ($lv -and $lv -ne 'All')  { $rows = @($rows | Where-Object Level -eq $lv) }
    if ($cat -and $cat -ne 'All') { $rows = @($rows | Where-Object Category -eq $cat) }
    if ($q) { $rows = @($rows | Where-Object { $_.Message -like "*$q*" -or $_.Admin -like "*$q*" -or $_.Tenant -like "*$q*" }) }
    $UI.LogGrid.ItemsSource = $rows
    $UI.LogCount.Text = "  $($rows.Count) entries (last 7 days)"
}

# ================================================================== main
function Start-MspTapApp {
    $script:Settings = Get-AppSettings
    Remove-OldLogs -RetentionDays ([int]$script:Settings.LogRetentionDays)
    $script:S.Inline = [bool]$script:Settings.RunInline

    $xaml = Get-Content (Join-Path $script:UiDir 'MainWindow.xaml') -Raw
    $script:Window = [System.Windows.Markup.XamlReader]::Parse($xaml)
    foreach ($m in [regex]::Matches($xaml, 'x:Name="([A-Za-z0-9_]+)"')) { $script:UI[$m.Groups[1].Value] = $script:Window.FindName($m.Groups[1].Value) }
    $UI = $script:UI

    $theme = if ($script:Settings.Theme -in 'Dark', 'Light') { $script:Settings.Theme } else { Get-SystemTheme }
    Set-Theme $theme

    # data bindings
    $UI.QueueGrid.ItemsSource = $script:Users; $UI.ReadyGrid.ItemsSource = $script:Ready; $UI.FailedGrid.ItemsSource = $script:FailedV
    $UI.LkGrid.ItemsSource = $script:Lookup;   $UI.ResultsGrid.ItemsSource = $script:Results
    $lifetimes = @(Get-LifetimeOption)
    $UI.LifetimeCombo.ItemsSource = $lifetimes
    $UI.LifetimeCombo.SelectedItem = $lifetimes | Where-Object Minutes -eq ([int]$script:Settings.DefaultLifetimeMins) | Select-Object -First 1
    if (-not $UI.LifetimeCombo.SelectedItem) { $UI.LifetimeCombo.SelectedIndex = 1 }
    $UI.LengthSlider.IsEnabled = $false
    $UI.LogLevel.ItemsSource = 'All', 'Info', 'Success', 'Warning', 'Error', 'Audit'; $UI.LogLevel.SelectedIndex = 0
    $UI.LogCategory.ItemsSource = 'All', 'App', 'Auth', 'Graph', 'Import', 'Export', 'Validation', 'Generation', 'Policy', 'UI'; $UI.LogCategory.SelectedIndex = 0
    $UI.StartBox.Text = (Get-Date).AddHours(1).ToString('yyyy-MM-dd HH:00')
    Update-ProfileList; Update-Header; Update-Dashboard; Update-QueueCount

    # ---- sign-in screen
    $UI.ProfileCombo.Add_SelectionChanged({
        $p = $script:UI.ProfileCombo.SelectedItem
        if ($p) { $script:UI.CustomerBox.Text = $p.CustomerName; $script:UI.TenantBox.Text = $p.TenantId }
    })
    $UI.SaveProfileBtn.Add_Click({
        try { Save-TenantProfile -CustomerName $script:UI.CustomerBox.Text -TenantId $script:UI.TenantBox.Text; Update-ProfileList; $script:UI.LoginStatus.Text = 'Customer saved (name and tenant ID only).' }
        catch { $script:UI.LoginStatus.Text = $_.Exception.Message }
    })
    $UI.DeleteProfileBtn.Add_Click({
        $p = $script:UI.ProfileCombo.SelectedItem
        if ($p) { Remove-TenantProfile -TenantId $p.TenantId; Update-ProfileList }
    })
    $UI.SignInBtn.Add_Click({ Start-SignIn })
    $UI.CancelSignInBtn.Add_Click({ if ($script:S.Cancel) { $script:S.Cancel.Cancel = $true }; $script:UI.LoginStatus.Text = 'Cancelling...' })
    $UI.CopyCodeBtn.Add_Click({ try { [System.Windows.Clipboard]::SetText($script:UI.DeviceCodeText.Text) } catch { } })
    $UI.OpenUriBtn.Add_Click({
        $u = $script:UI.DeviceUriText.Text
        if ($u -match '^https://(microsoft\.com|login\.microsoftonline\.com|www\.microsoft\.com)/') { Start-Process $u }
    })
    $UI.SignOutBtn.Add_Click({ Invoke-SignOut })
    $UI.SwitchTenantBtn.Add_Click({ Invoke-SignOut; if (-not $script:S.Identity) { $script:UI.LoginStatus.Text = 'Choose the next customer tenant.' } })
    $UI.ThemeBtn.Add_Click({
        $n = if ($script:S.Theme -eq 'Dark') { 'Light' } else { 'Dark' }
        Set-Theme $n; $script:Settings.Theme = $n; Save-AppSettings $script:Settings
    })
    $UI.RefreshPolicyBtn.Add_Click({ if ($script:S.Identity) { Refresh-Policy } })

    # ---- import
    $UI.CsvBrowseBtn.Add_Click({ $f = Select-File 'CSV files (*.csv;*.txt)|*.csv;*.txt|All files|*.*'; if ($f) { $script:UI.CsvPath.Text = $f } })
    $UI.CsvLoadBtn.Add_Click({
        try {
            $r = Import-UsersFromCsv -Path $script:UI.CsvPath.Text.Trim('"', ' ')
            $m = Add-UsersToQueue $r.Users 'CSV'
            $script:UI.CsvMsg.Text = "$m.$(Format-Skipped $r.Skipped)"
            Write-AppLog -Category Import -Message "CSV import: $m; skipped $(@($r.Skipped).Count)"
        } catch { $script:UI.CsvMsg.Text = $_.Exception.Message; Write-AppLog -Level Error -Category Import -Message "CSV import failed: $($_.Exception.Message)" }
    })
    $UI.XlsxBrowseBtn.Add_Click({
        $f = Select-File 'Excel workbooks (*.xlsx)|*.xlsx'
        if (-not $f) { return }
        $script:UI.XlsxPath.Text = $f
        try { $s = @(Get-XlsxSheetName -Path $f); $script:UI.XlsxSheet.ItemsSource = $s; $script:UI.XlsxSheet.SelectedIndex = 0; $script:UI.XlsxMsg.Text = "$($s.Count) sheet(s) found." }
        catch { $script:UI.XlsxMsg.Text = $_.Exception.Message }
    })
    $UI.XlsxSheet.Add_SelectionChanged({ Update-XlsxColumns })
    $UI.XlsxLoadBtn.Add_Click({
        $UI = $script:UI
        try {
            if (-not $UI.XlsxSheet.SelectedItem -or -not $UI.XlsxUpnCol.SelectedItem) { throw 'Choose the sheet and the UserPrincipalName column.' }
            $nm = if ($UI.XlsxNameCol.SelectedItem -and $UI.XlsxNameCol.SelectedItem -ne '(none)') { $UI.XlsxNameCol.SelectedItem } else { '' }
            $r = Import-UsersFromXlsx -Path $UI.XlsxPath.Text.Trim('"', ' ') -Sheet $UI.XlsxSheet.SelectedItem -UpnColumn $UI.XlsxUpnCol.SelectedItem -DisplayNameColumn $nm
            $m = Add-UsersToQueue $r.Users 'XLSX'
            $UI.XlsxMsg.Text = "$m.$(Format-Skipped $r.Skipped)"
            Write-AppLog -Category Import -Message "XLSX import ($($UI.XlsxSheet.SelectedItem)): $m; skipped $(@($r.Skipped).Count)"
        } catch { $UI.XlsxMsg.Text = $_.Exception.Message; Write-AppLog -Level Error -Category Import -Message "XLSX import failed: $($_.Exception.Message)" }
    })
    $UI.LkFindGroupsBtn.Add_Click({
        $t = $script:UI.LkGroupSearch.Text.Trim(); if (-not $t) { return }
        Start-AppTask -Command 'Find-TapGroup' -Params @{ SearchText = $t } -BusyText 'Searching groups...' `
            -OnDone { param($res) $g = @($res | Where-Object { $_ }); $script:UI.LkGroup.ItemsSource = $g; if ($g.Count) { $script:UI.LkGroup.SelectedIndex = 0 }; $script:UI.LkMsg.Text = "$($g.Count) group(s) found." } `
            -OnError { param($m) $script:UI.LkMsg.Text = "Group search failed: $m" }
    })
    $UI.LkSearchBtn.Add_Click({
        if (-not $script:S.Identity) { return }
        $script:UI.LkMsg.Text = 'Searching...'
        Start-AppTask -Command 'Get-TapUserLookup' -Params (Get-LookupParams) -BusyText 'Searching Entra...' `
            -OnDone {
                param($res)
                $script:Lookup.Clear()
                foreach ($u in @($res | Where-Object { $_ })) {
                    $r = [MspTap.UserRow]::new(); $r.UserPrincipalName = $u.UserPrincipalName; $r.DisplayName = $u.DisplayName; $r.Department = $u.Department; $r.JobTitle = $u.JobTitle; $r.Id = $u.Id; $r.Source = 'Entra'
                    $script:Lookup.Add($r)
                }
                $script:UI.LkMsg.Text = "$($script:Lookup.Count) user(s) found."
                Write-AppLog -Category Graph -Message "Entra lookup returned $($script:Lookup.Count) user(s)."
            } `
            -OnError { param($m) $script:UI.LkMsg.Text = "Search failed: $m"; Write-AppLog -Level Error -Category Graph -Message "Lookup failed: $m" }
    })
    $UI.LkAddSelBtn.Add_Click({ Add-LookupToQueue @($script:UI.LkGrid.SelectedItems) })
    $UI.LkAddAllBtn.Add_Click({ Add-LookupToQueue @($script:Lookup) })

    $UI.SelAllBtn.Add_Click({ foreach ($u in $script:Users) { $u.Selected = $true }; Update-QueueCount })
    $UI.SelNoneBtn.Add_Click({ foreach ($u in $script:Users) { $u.Selected = $false }; Update-QueueCount })
    $UI.RemoveSelBtn.Add_Click({
        foreach ($u in @($script:Users | Where-Object Selected)) { [void]$script:Users.Remove($u) }
        Rebuild-UserIndex; Reset-Validation; Update-QueueCount; Update-Dashboard
    })
    $UI.ClearQueueBtn.Add_Click({ $script:Users.Clear(); Rebuild-UserIndex; Reset-Validation; Update-QueueCount; Update-Dashboard })

    # ---- generate
    $UI.LengthSlider.Add_ValueChanged({ $script:UI.LengthText.Text = [int]$script:UI.LengthSlider.Value })
    $UI.ApplyLengthCheck.Add_Click({ $script:UI.LengthSlider.IsEnabled = [bool]$script:UI.ApplyLengthCheck.IsChecked })
    $UI.DelayCheck.Add_Click({ $script:UI.StartBox.IsEnabled = [bool]$script:UI.DelayCheck.IsChecked })
    $UI.ValidateBtn.Add_Click({ Start-Validation })
    $UI.GenerateBtn.Add_Click({ Start-Generation -Rows @($script:Ready) })
    $UI.CancelBtn.Add_Click({ if ($script:S.Cancel) { $script:S.Cancel.Cancel = $true; Set-Status 'Cancelling after the current user...' } })
    $UI.RetryBtn.Add_Click({
        $failed = @($script:Results | Where-Object Status -eq 'Failed' | ForEach-Object { $script:UserIndex[$_.UserPrincipalName.ToLowerInvariant()] } | Where-Object { $_ -and $_.Id })
        if ($failed.Count -eq 0) { Show-Msg 'No retryable failures.'; return }
        Start-Generation -Rows $failed -IsRetry $true
    })
    $UI.ExportFailBtn.Add_Click({ Export-Failures })

    # ---- results
    $UI.RevealToggle.Add_Checked({
        foreach ($r in $script:Results) { if ($r.HasTap) { $r.Reveal = $true } }
        $script:UI.RevealToggle.Content = 'Hide TAPs'
        $script:S.HideDeadline = (Get-Date).AddSeconds([int]$script:Settings.AutoHideTapSecs)
        Write-AppLog -Category UI -Message 'TAPs revealed on screen.'
    })
    $UI.RevealToggle.Add_Unchecked({
        foreach ($r in $script:Results) { $r.Reveal = $false }
        $script:UI.RevealToggle.Content = 'Show TAPs'; $script:S.HideDeadline = $null
    })
    $UI.CopyRowBtn.Add_Click({ Copy-Rows @($script:UI.ResultsGrid.SelectedItem) })
    $UI.CopySelBtn.Add_Click({ Copy-Rows (Get-ResultRows -SelectedOnly) })
    $UI.MiCopyTap.Add_Click({ Copy-Rows (Get-ResultRows -SelectedOnly) -TapOnly })
    $UI.MiReveal.Add_Click({ foreach ($r in (Get-ResultRows -SelectedOnly)) { if ($r.HasTap) { $r.Reveal = -not $r.Reveal } }; $script:S.HideDeadline = (Get-Date).AddSeconds([int]$script:Settings.AutoHideTapSecs) })
    $UI.ExportBtn.Add_Click({ Export-Results })
    $UI.EncryptCheck.Add_Click({ $script:UI.XlsxPassword.IsEnabled = [bool]$script:UI.EncryptCheck.IsChecked })
    $UI.ClearResultsBtn.Add_Click({
        if ((Show-Msg 'Remove all TAP values from memory? They cannot be recovered afterwards.' 'Clear TAPs' 'YesNo' 'Question') -eq 'Yes') {
            foreach ($r in $script:Results) { $r.ClearTap() }; Clear-LogSecrets; $script:UI.RevealToggle.IsChecked = $false
            Write-AppLog -Category UI -Message 'TAP values cleared from memory by user.'
        }
    })

    # ---- logs
    $UI.LogRefreshBtn.Add_Click({ Update-LogView })
    $UI.LogLevel.Add_SelectionChanged({ if ($script:UI.LogGrid) { Update-LogView } })
    $UI.LogCategory.Add_SelectionChanged({ if ($script:UI.LogGrid) { Update-LogView } })
    $UI.LogSearch.Add_KeyDown({ param($s, $e) if ($e.Key -eq 'Return') { Update-LogView } })
    $UI.LogFolderBtn.Add_Click({ Start-Process explorer.exe (Get-LogDirectory) })
    $UI.MainTabs.Add_SelectionChanged({
        param($s, $e)
        if ($e.OriginalSource -ne $script:UI.MainTabs) { return }
        $h = $script:UI.MainTabs.SelectedItem.Header
        if ($h -eq 'Logs') { Update-LogView } elseif ($h -eq 'Dashboard') { Update-Dashboard }
    })

    # ---- pump timer: task messages, clipboard clearing, auto-hide
    $script:Pump = [System.Windows.Threading.DispatcherTimer]::new()
    $script:Pump.Interval = [timespan]::FromMilliseconds(100)
    $script:Pump.Add_Tick({
        Invoke-TaskPump
        $script:Tick++
        if ($script:Tick % 5 -eq 0) {
            if ($script:UI.MainTabs.SelectedIndex -eq 1) { Update-QueueCount }
            if ($script:S.ClipDeadline -and (Get-Date) -gt $script:S.ClipDeadline) { Clear-ClipboardIfOurs; Set-Status 'Clipboard cleared.' }
            if ($script:S.HideDeadline -and (Get-Date) -gt $script:S.HideDeadline) { $script:UI.RevealToggle.IsChecked = $false }
        }
    })
    $script:Pump.Start()

    $script:Window.Dispatcher.Add_UnhandledException({
        param($s, $e)
        $e.Handled = $true
        Write-AppLog -Level Error -Category UI -Message "Unhandled UI error: $($e.Exception.Message)"
        Set-Status "Unexpected error: $($e.Exception.Message) (see Logs)"
    })
    $script:Window.Add_Closing({
        param($s, $e)
        $pending = @($script:Results | Where-Object HasTap).Count
        if ($pending -gt 0 -and (Show-Msg "$pending TAP(s) have not been cleared. Closing discards them.`n`nClose anyway?" 'Close' 'YesNo' 'Warning') -ne 'Yes') { $e.Cancel = $true; return }
        $script:Pump.Stop()
        foreach ($r in $script:Results) { $r.ClearTap() }
        Clear-ClipboardIfOurs
        if ($script:S.Identity) { Disconnect-TapGraph }
        Clear-LogSecrets
        Write-AppLog -Category App -Message 'Application closed.'
        if ($script:Pool) { try { $script:Pool.Close(); $script:Pool.Dispose() } catch { } }
    })

    Write-AppLog -Category App -Message "Application started (PowerShell $($PSVersionTable.PSVersion), inline mode: $($script:S.Inline))."
    Initialize-WorkerPool
    [void]$script:Window.ShowDialog()
}
~~~~

---

## `tests/MspTap.Tests.ps1`

~~~~powershell
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
BeforeAll {
    $env:LOCALAPPDATA = $TestDrive
    $src = Join-Path $PSScriptRoot '..\src\Modules'
    Import-Module (Join-Path $src 'MspTap.Core\MspTap.Core.psm1') -Force -Global
    Import-Module (Join-Path $src 'MspTap.Data\MspTap.Data.psm1') -Force -Global
    $samples = Join-Path $PSScriptRoot '..\samples'
}

Describe 'Log scrubbing (TAP must never reach the log)' {
    It 'redacts registered TAP values' {
        Register-LogSecret 'Xk9#fT2pQ7zL'
        Protect-LogText 'created Xk9#fT2pQ7zL for bob' | Should -Be 'created [REDACTED] for bob'
    }
    It 'redacts a TAP at the end of a sentence or inside key=value' {
        Register-LogSecret 'EndOfSentence77'
        Protect-LogText 'the pass is EndOfSentence77.' | Should -Be 'the pass is [REDACTED].'
        Protect-LogText 'tap=EndOfSentence77;' | Should -Be 'tap=[REDACTED];'
    }
    It 'keeps only hashes, never the plain value, in the registry' {
        Register-LogSecret 'PlainValueCheck9'
        (Get-SecretRegistry).Keys | Should -Not -Contain 'PlainValueCheck9'
        Clear-LogSecrets
        Protect-LogText 'PlainValueCheck9' | Should -Be 'PlainValueCheck9'
    }
    It 'redacts temporaryAccessPass JSON members' {
        Protect-LogText '{"temporaryAccessPass":"abc123XYZ","x":1}' | Should -Not -Match 'abc123XYZ'
    }
    It 'redacts bearer tokens' { Protect-LogText 'Authorization: Bearer abcDEF123.456' | Should -Not -Match 'abcDEF123' }
    It 'never writes a registered TAP to the log file' {
        Register-LogSecret 'SuperSecretTap99'
        Write-AppLog -Message 'result SuperSecretTap99 done'
        (Get-ChildItem (Get-LogDirectory) -Filter *.jsonl | Get-Content -Raw) | Should -Not -Match 'SuperSecretTap99'
    }
}

Describe 'Validation helpers' {
    It 'accepts GUID and domain tenant ids' {
        Test-TenantIdentifier '11111111-2222-3333-4444-555555555555' | Should -BeTrue
        Test-TenantIdentifier 'contoso.onmicrosoft.com' | Should -BeTrue
    }
    It 'rejects junk tenant ids' { Test-TenantIdentifier "x'; drop" | Should -BeFalse }
    It 'checks UPN shape' { Test-UpnFormat 'a@b.co' | Should -BeTrue; Test-UpnFormat 'nope' | Should -BeFalse }
    It 'neutralises spreadsheet formulas' { Protect-ExportCell '=HYPERLINK("x")' | Should -Be "'=HYPERLINK(`"x`")" }
}

Describe 'Invoke-WithRetry' {
    It 'retries 429 then succeeds' {
        $script:n = 0
        $r = Invoke-WithRetry -BaseDelaySeconds 0 -MaxAttempts 4 { $script:n++; if ($script:n -lt 3) { throw 'Response status code does not indicate success: 429 (Too Many Requests).' }; 'ok' }
        $r | Should -Be 'ok'; $script:n | Should -Be 3
    }
    It 'does not retry a 404' {
        $script:n = 0
        { Invoke-WithRetry -BaseDelaySeconds 0 { $script:n++; throw 'Request_ResourceNotFound' } } | Should -Throw
        $script:n | Should -Be 1
    }
    It 'gives up after MaxAttempts' {
        $script:n = 0
        { Invoke-WithRetry -BaseDelaySeconds 0 -MaxAttempts 2 { $script:n++; throw '429 TooManyRequests' } } | Should -Throw
        $script:n | Should -Be 2
    }
}

Describe 'CSV import' {
    It 'reads a UPN-only file' {
        $r = Import-UsersFromCsv (Join-Path $samples 'users.csv'); $r.Users.Count | Should -Be 2
    }
    It 'reads UPN + DisplayName' {
        $r = Import-UsersFromCsv (Join-Path $samples 'users_with_names.csv'); $r.Users[0].DisplayName | Should -Be 'Joe Bloggs'
    }
    It 'skips duplicates and malformed rows' {
        $f = Join-Path $TestDrive 'bad.csv'
        "UserPrincipalName`na@x.com`nA@x.com`nnotanupn`n" | Set-Content $f
        $r = Import-UsersFromCsv $f; $r.Users.Count | Should -Be 1; $r.Skipped.Count | Should -Be 2
    }
    It 'handles semicolon delimiters' {
        $f = Join-Path $TestDrive 'semi.csv'; "UPN;Name`na@x.com;Al`n" | Set-Content $f
        (Import-UsersFromCsv $f).Users[0].DisplayName | Should -Be 'Al'
    }
    It 'errors when no UPN column exists' {
        $f = Join-Path $TestDrive 'nocol.csv'; "Foo,Bar`n1,2`n" | Set-Content $f
        { Import-UsersFromCsv $f } | Should -Throw '*No UserPrincipalName*'
    }
}

Describe 'XLSX round trip' -Skip:(-not (Get-Module -ListAvailable ImportExcel)) {
    It 'exports, masks TAPs and re-imports sheet names' {
        $p = Join-Path $TestDrive 'out.xlsx'
        $row = [pscustomobject]@{ UserPrincipalName = 'a@x.com'; DisplayName = '=cmd'; Tap = (ConvertTo-SecureString 'TopSecret12' -AsPlainText -Force)
            TapLength = 11; OneTimeUse = $true; StartUtc = [datetime]::UtcNow; ExpiryUtc = [datetime]::UtcNow.AddHours(1); Status = 'Success' }
        Export-TapResult -Rows $row -Path $p -MaskTap
        (Import-Excel $p).TAP | Should -Be '********'
        (Import-Excel $p).DisplayName | Should -Be "'=cmd"
        Get-XlsxSheetName $p | Should -Contain 'TAPs'
    }
}
~~~~

---

## `samples/users.csv`

~~~~csv
UserPrincipalName
user1@contoso.com
user2@contoso.com
~~~~

---

## `samples/users_with_names.csv`

~~~~csv
UserPrincipalName,DisplayName
user1@contoso.com,Joe Bloggs
user2@contoso.com,Jane Doe
~~~~

---

## `.gitignore`

~~~~text
dist/
*.sha256
~~~~

---

## `README.md`

~~~~markdown
# MSP TAP Generator

A Windows desktop tool for MSPs. It creates Microsoft Entra **Temporary Access Passes (TAPs)** in bulk, so you can get a batch of devices through Windows Autopilot without chasing passwords.

PowerShell 7 + WPF. Uses the Microsoft Graph PowerShell SDK. Works across many customer tenants. Stores no credentials.

> **Status:** written and reviewed by hand, but I could not run it on Windows when I built it (the build environment was Linux with no PowerShell). Treat the first run as a pilot: try it against a test tenant with 2 or 3 users before a real batch. See "Pilot checklist" at the bottom.

## What it does

- Sign in per customer: interactive browser or device code. Pick the tenant first.
- Load users from **CSV**, **XLSX** (pick the sheet and map the columns) or **Entra** (search, department, job title, group).
- Check everything before it creates anything: permissions, TAP policy, user exists, account enabled, not a guest.
- Create TAPs with a lifetime, one-time use, and optional delayed start.
- Progress with counts, current user and ETA. Retry failures. Export failures.
- Results grid with the TAP masked. Show/hide, copy, export to `TAPs_YYYYMMDD_HHMMSS.xlsx`.
- Dark and light theme. The customer name and tenant ID are shown in the banner at all times.

## One thing you need to know about "password length"

Microsoft Graph cannot set the length of a single TAP. Length is a **tenant-wide policy setting** (`defaultLength`, 8-48).

So the length slider works like this:

- By default it is locked and shows the tenant's current length (read from the policy).
- If you tick **Apply this length to the tenant TAP policy**, the tool changes the policy before the batch and (by default) puts the old value back afterwards.
- That needs one extra permission, `Policy.ReadWrite.AuthenticationMethod`, which you opt into on the sign-in screen. It changes a setting for the whole tenant, so you get a confirmation first.
- The `TAPLength` column in the export is the real length of each pass that came back, not the slider value.

## Folder structure

```
MspTapGenerator/
  Start-MspTapGenerator.ps1      entry point (checks modules, loads UI)
  Install-Prerequisites.ps1      installs Graph SDK + ImportExcel
  Build-Package.ps1              lint, test, sign (optional), zip
  src/
    Modules/
      MspTap.Core/               logging + TAP scrubbing, settings, tenant profiles, retry/back-off
      MspTap.Data/               CSV / XLSX import, XLSX export
      MspTap.Graph/              sign-in, policy, lookup, validation, TAP creation, batch workers
    UI/
      MainWindow.xaml            layout
      Theme.Dark.xaml / Theme.Light.xaml
      UiTypes.cs                 row classes for the grids (TAP held as SecureString)
      App.UI.ps1                 code-behind, task runner, handlers
  tests/MspTap.Tests.ps1         Pester 5 tests (no Graph needed)
  samples/                       example CSV files
  docs/                          SECURITY, GRAPH-PERMISSIONS, ERROR-HANDLING, APP-REGISTRATION
```

## Requirements

- Windows 10/11 or Server 2019+ (WPF)
- PowerShell **7.2 or later** (`winget install Microsoft.PowerShell`)
- Modules: `Microsoft.Graph.Authentication`, `.Users`, `.Groups`, `.Identity.SignIns`, `.Identity.DirectoryManagement` (2.10.0+), and `ImportExcel` (7.8+). Excel is **not** needed.
- Internet access to `login.microsoftonline.com` and `graph.microsoft.com`

## Install

```powershell
# 1. get the folder onto the machine (zip from Build-Package, or clone), then:
Unblock-File -Path .\*.ps1 -ErrorAction SilentlyContinue
Get-ChildItem -Recurse -Include *.ps1,*.psm1,*.xaml,*.cs | Unblock-File

# 2. install modules (per user, no admin needed)
pwsh -File .\Install-Prerequisites.ps1

# 3. run
pwsh -STA -File .\Start-MspTapGenerator.ps1
```

If scripts are blocked by policy, either sign them (see Build) or run `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser`.

## Build

```powershell
pwsh -File .\Build-Package.ps1                       # lint + tests + zip into dist\
pwsh -File .\Build-Package.ps1 -CertThumbprint <thumbprint>   # also code-sign every script
pwsh -File .\Build-Package.ps1 -SkipTests
```

The output is `dist\MspTapGenerator-<version>.zip` plus a `.sha256` file. Unzip, run `Install-Prerequisites.ps1`, then `Launch.cmd`. There is no compile step. It is scripts, XAML and one small C# file that PowerShell compiles at start-up.

Run tests on their own: `Invoke-Pester .\tests`

## Using it

1. **Sign in.** Choose a saved customer or type the tenant ID or domain. Choose Interactive or Device code. Saved customers keep the name and tenant ID only.
2. **Import Users.** Add users from CSV, XLSX or Entra. They land in the work queue (tick/untick, remove). Duplicates are dropped.
3. **Generate TAPs.** Set lifetime and options, click **Validate**, read the results (failures show in their own grid), then **Generate TAPs**. You get a confirmation naming the customer and tenant ID.
4. **Results.** TAPs are masked. Use Show TAPs, Copy row/selected, or Export XLSX.
5. **Logs.** Filter by level or category. Audit entries record who signed in to which tenant, the ticket / change reference, and what was run (never the TAP).

CSV formats accepted (header names are not case sensitive, `UPN`, `Email` and `Name` also work):

```
UserPrincipalName
user1@contoso.com
```
```
UserPrincipalName,DisplayName
user1@contoso.com,Joe Bloggs
```

## Roles the signed-in admin needs

The Graph permissions are only half of it. The admin account also needs an Entra role in the customer tenant:

- **Authentication Administrator**: can create TAPs for non-admin users.
- **Privileged Authentication Administrator**: needed to create TAPs for users who hold admin roles.

For partners using GDAP, the relationship must include one of those roles. PIM-eligible roles must be activated first.

## Multi-tenant notes (important for MSPs)

- The first sign-in to a customer tenant needs **admin consent** for the delegated permissions. The default app (Microsoft Graph Command Line Tools) often cannot be consented by a GDAP partner account.
- The clean fix is your own multi-tenant app registration (step-by-step in `docs/APP-REGISTRATION.md`): public client, redirect `http://localhost`, "Allow public client flows = Yes" (for device code), delegated permissions as listed in `docs/GRAPH-PERMISSIONS.md`. Each customer consents once. Paste its client ID under **Advanced** on the sign-in screen, or set `ClientId` in `%LOCALAPPDATA%\MspTapGenerator\settings.json`.
- If you type a tenant GUID and Entra signs you in to a different tenant, the tool signs you straight back out.
- Switching tenant clears the queue and all TAPs from memory.

## Known limits

- TAP length is policy-level (see above).
- Users are validated one by one with `Get-MgUser`. For several thousand users validation takes a while. It is steady and throttle-safe rather than fast.
- TAP creation is deliberately sequential. Graph throttles writes per tenant, so parallel calls would only trigger 429s.
- A user can only have one usable TAP. Creating a new one replaces the old one (Microsoft's behaviour). Validation flags these users as a warning and the confirmation prompt counts them.
- A TAP can only be created if the tenant policy allows the lifetime you pick. Default tenant policy is 1 hour minimum, 8 hours maximum, so `30 minutes`, `24 hours` and `7 days` will be rejected until the policy range is widened. The pre-flight check tells you before anything is created.
- If the Graph sign-in is not visible to the worker thread on your machine, the app switches itself to "compatibility mode" and runs Graph calls on the UI thread (window may pause briefly). You will see a note on the sign-in screen.
- "Clear from memory" is best effort. See `docs/SECURITY.md`.

## Open questions worth answering before roll-out

- Which customers are on GDAP and which have their own admin accounts? That decides how consent works.
- Do you want your own app registration (recommended) or the Microsoft one?
- Is the TAP policy enabled and targeted at "All users" for each customer, or only a group?
- Where should exported workbooks live, and who is allowed to open them? Suggest a password-protected workbook on an encrypted drive.

## Pilot checklist

- [ ] `Install-Prerequisites.ps1` finishes clean
- [ ] App opens, theme toggle works in both modes
- [ ] Interactive sign-in to a test tenant shows the right customer name and tenant ID
- [ ] Device-code sign-in works (code shown in window)
- [ ] Import each of CSV, XLSX, Entra lookup
- [ ] Validate flags a disabled user, a missing user and a guest
- [ ] Generate for 2-3 users, check the TAP works at an Autopilot sign-in
- [ ] Export masked and unmasked, open the files
- [ ] Open the log file and confirm no TAP value appears anywhere
- [ ] Sign out, sign in to a second tenant, confirm the queue was cleared
~~~~

---

## `docs/SECURITY.md`

~~~~markdown
# Security design

## What the tool stores on disk

| Item | Where | Notes |
|---|---|---|
| Settings (theme, client ID, timeouts) | `%LOCALAPPDATA%\MspTapGenerator\settings.json` | No secrets |
| Tenant profiles | `%LOCALAPPDATA%\MspTapGenerator\profiles.json` | Customer name + tenant ID only |
| Logs | `%LOCALAPPDATA%\MspTapGenerator\Logs\mspTap_YYYYMMDD.jsonl` | Deleted after 90 days (setting) |
| Exports | wherever the admin saves them | The only place a TAP can be written, and only if the admin chooses an unmasked export |

No passwords, access tokens or refresh tokens are saved. Interactive sign-in uses `-ContextScope Process`, so the Graph SDK does not persist a token cache. The device-code refresh token lives in process memory only (a `SecureString`), and is wiped on sign-out.

## TAP handling

1. The SDK returns the TAP as a plain string. It is converted to a `SecureString` immediately and the property on the response object is nulled.
2. Rows in the results grid hold the `SecureString`. Plain text exists only while: the grid is revealed, a value is being copied, or a file is being exported.
3. The grid is masked by default and **auto-hides** after 30 seconds.
4. **Log scrubbing.** TAP values are never passed to the logger. As a second layer, each TAP's **SHA-256 hash** (never the value) is registered, and `Protect-LogText` hashes every token in a log line and redacts matches (also bearer tokens, JWTs, and `temporaryAccessPass` JSON members in echoed Graph errors). Tested in `tests/MspTap.Tests.ps1`.
5. **Clipboard.** Copies are flagged `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory=0`, `CanUploadToCloudClipboard=0` (no Win+V history, no cloud sync) and cleared after 60 seconds if the clipboard still holds the same value (compared by hash).
6. **Export.** Masked by default (`********`). If unmasked and not password-protected, the admin gets a warning. Optional AES-encrypted workbook. After an unmasked export the TAPs are cleared from memory (default on).
7. Sign-out, tenant switch and closing the window all clear TAP values and warn first if any are still held.

**Honest limit:** .NET strings are immutable and the garbage collector may leave copies in memory until collected. A `SecureString` reduces exposure; it does not make memory forensics impossible. The Graph SDK's own response object also briefly holds the plain value. Treat the workstation as in scope for the same controls you use for a password vault: disk encryption, EDR, locked screen.

## Authentication

- Interactive (MSAL via `Connect-MgGraph`) or OAuth2 device code (shown in the app, then `Connect-MgGraph -AccessToken`).
- Tenant is always explicit. If a GUID was requested and a different tenant comes back, the session is dropped.
- A confirmation naming the customer and tenant ID appears before every generation run. This is the main guard against creating passes in the wrong customer.
- Use your own app registration where you can. Conditional Access applies as normal (use a compliant device and phishing-resistant MFA for the admin account).

## Other hardening

- Spreadsheet formula injection: display names starting with `= + - @` are prefixed with `'` on export.
- OData filter values are escaped (`'` doubled); search text has quotes stripped.
- CSV size limit 20 MB. Imports validate UPN shape and drop duplicates.
- The "Open page" button only opens `https://microsoft.com`, `microsoft.com` or `login.microsoftonline.com` URLs.
- Workbook passwords are read from a `PasswordBox` and not stored or logged.
- Package signing supported through `Build-Package.ps1 -CertThumbprint`.

## Audit trail

`Audit` log entries record: sign-in (tenant, admin, scopes), each generation batch (counts, lifetime, one-time, delayed start), policy length changes, exports (file name, masked or not, encrypted or not). Each line carries session ID, customer name, tenant ID and admin UPN. User UPNs appear in per-user result lines. Every line also carries the **ticket / change reference** typed on the Generate tab (shown in the confirmation prompt, written to the log, and stored in the exported workbook's Subject property). Set `"RequireTicket": true` in `settings.json` to make it mandatory.
~~~~

---

## `docs/GRAPH-PERMISSIONS.md`

~~~~markdown
# Graph permission model

All permissions are **delegated** (the tool acts as the signed-in admin). Nothing is app-only.

| Permission | Required | Why |
|---|---|---|
| `User.Read.All` | Yes | `Get-MgUser`: search, filters, validation (exists / enabled / member) |
| `UserAuthenticationMethod.ReadWrite.All` | Yes | Create TAPs; read existing TAPs. Needs admin consent. |
| `Directory.Read.All` | Yes | Organization name, group membership, admin role check |
| `AuditLog.Read.All` | Yes | Requested as specified. Reserved for sign-in/audit checks; not needed for creating TAPs |
| `Policy.Read.All` | Optional (on by default) | Read the TAP policy: enabled, lifetime range, one-time-only, length, targets |
| `Policy.ReadWrite.AuthenticationMethod` | Optional (off by default) | Only when you tick "Apply this length to the tenant TAP policy" |

`UserAuthMethod-TAP.ReadWrite.All` is a narrower permission that Microsoft lists for creating TAPs. It would work for creation only. The tool keeps `UserAuthenticationMethod.ReadWrite.All` as you specified.

Without `Policy.Read.All` everything still works. The policy shows as "Unknown" and the lifetime/enabled checks are skipped (Graph then rejects bad requests itself).

## Entra roles (the signed-in admin)

| Role | Can create TAPs for |
|---|---|
| Authentication Administrator | Non-admin members |
| Privileged Authentication Administrator | Any user including admins |
| Global Administrator | Any user |

Guests cannot use TAP. The validation step marks them as failed.

## Cmdlets and endpoints used

| Action | Cmdlet / call |
|---|---|
| Sign in | `Connect-MgGraph -Scopes ... -ContextScope Process` or `-AccessToken` after device code |
| Tenant name | `Get-MgOrganization` |
| Find users | `Get-MgUser -Filter/-Search -ConsistencyLevel eventual` |
| Group members | `Get-MgGroupTransitiveMemberAsUser`, `Get-MgGroup -Search` |
| Validate user | `Get-MgUser -UserId`, `Get-MgUserAuthenticationTemporaryAccessPassMethod` |
| **Create TAP** | `New-MgUserAuthenticationTemporaryAccessPassMethod` (`lifetimeInMinutes`, `isUsableOnce`, `startDateTime`) |
| Policy read/write | `Invoke-MgGraphRequest` on `/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/TemporaryAccessPass` |
| Admin roles | `Invoke-MgGraphRequest` on `/me/transitiveMemberOf/microsoft.graph.directoryRole` |

## Throttling

429, 503 and 504 are retried up to 6 times with exponential back-off (2, 4, 8... up to 60 seconds) plus up to 1 second of jitter. `Retry-After` is honoured when Graph sends it. Creation is sequential with a 150 ms pause. Other errors are not retried. 3 authorization failures in a row stop the batch.
~~~~

---

## `docs/ERROR-HANDLING.md`

~~~~markdown
# Error handling strategy

**Principle:** one bad user never stops a batch, one bad batch never loses results, and nothing sensitive ends up in an error message.

| Layer | What happens |
|---|---|
| Pre-flight (before any write) | Missing scopes, TAP method disabled, lifetime outside policy range, activation time in the past: **stop with a clear message**. Unreadable policy or unverifiable admin role: **warn and continue**. |
| Per-user validation | Not found, disabled, guest = `Failed` (shown in the separate failures grid). Existing TAP = `Warning`. Nothing is created for `Failed` users. |
| Throttling / transient | 429/503/504 retried with exponential back-off and jitter. Progress keeps running. Cancel works during a wait. |
| Per-user creation failure | Recorded on the row with a friendly reason plus the Graph error code, then the batch moves on. |
| Repeated 401/403 | After 3 in a row the batch stops (almost always a missing role or consent). Results so far are kept. |
| Token expiry | Interactive: MSAL refreshes. Device code: the app refreshes with the in-memory refresh token 5 minutes before expiry. |
| Cancel | Stops after the current user. Partial results stay in the grid. |
| Policy length change | Restored in a `finally` block even if the batch fails or is cancelled. If restore fails, a warning tells you the old value to set manually. |
| Worker problems | If background workers cannot be used (pool will not open, or Graph sign-in not shared with the worker) the app falls back to running Graph calls on the UI thread. |
| UI exceptions | Caught by the dispatcher handler, logged, shown in the status bar. The app stays open. |
| Import / export | Bad rows are skipped and counted with reasons. File problems show a message in the tab. Export failures never clear TAPs. |
| Logging | Never throws. Every message passes through `Protect-LogText`. |

## Friendly messages

| Graph result | Shown as |
|---|---|
| 403 | Signed-in admin needs Authentication Administrator (or Privileged Authentication Administrator for admin users) |
| 404 | User not found |
| 400, policy wording | TAP is not enabled for this user in the Authentication methods policy |
| 429 exhausted | Throttled by Graph and retries were used up. Retry failures later |
| 401 | Session expired. Sign in again |

The raw Graph code and message are appended in square brackets (scrubbed) so you can search them or send them to Microsoft.

## Retry and recovery

- **Retry failures** re-runs only users whose result row is `Failed`, with the current options, after a fresh confirmation.
- **Export failures** writes `TAP_Failures_<timestamp>.xlsx` (validation and generation failures, with stage and reason).
~~~~

---

## `docs/APP-REGISTRATION.md`

~~~~markdown
# Setting up your own app registration

Do this once, in **your MSP tenant**. Then each customer consents once. About 15 minutes.

## Why bother
Sign-ins show your app name instead of "Microsoft Graph Command Line Tools". You choose the permissions. Customers can review and revoke one clearly named app. Consent is easier to get than for the Microsoft app. See the comparison in the README.

## 1. Create the registration
Entra admin centre, **App registrations**, **New registration**.

| Setting | Value |
|---|---|
| Name | `MSP TAP Generator` (customers will see this) |
| Supported account types | **Accounts in any organizational directory (Multitenant)** |
| Redirect URI | Platform **Mobile and desktop applications**, value `http://localhost` |

Copy the **Application (client) ID**. This is the only value the tool needs. There is no secret, and you should not create one.

## 2. Allow device code sign-in
**Authentication**, then **Advanced settings**, then **Allow public client flows = Yes**. Save.

## 3. Add the permissions
**API permissions**, **Add a permission**, **Microsoft Graph**, **Delegated permissions**. Add:

- `User.Read.All`
- `UserAuthenticationMethod.ReadWrite.All`
- `Directory.Read.All`
- `AuditLog.Read.All`
- `Policy.Read.All` (optional, lets the tool read the TAP policy)
- `Policy.ReadWrite.AuthenticationMethod` (optional, only if you will change TAP length)

Do not add application permissions. Do not click grant admin consent in your own tenant unless you also want to use the tool there.

Tip: set the **Publisher domain** and a logo. A verified publisher makes the customer's consent screen less scary.

## 4. Get each customer to consent
A customer **Global Administrator** (or Privileged Role Administrator) opens this link while signed in to their tenant. Replace the two values:

```
https://login.microsoftonline.com/<customer-tenant-id>/adminconsent?client_id=<your-client-id>
```

They review the list and accept. Afterwards the app appears under their **Enterprise applications**.

Send the link in your onboarding email. Keep a record of who consented and when (ticket number).

If you use GDAP: only try to consent yourself if the relationship includes a role that is allowed to grant consent. If it does not, ask the customer. Consent for delegated permissions does not give you access by itself. Your admin still needs the Entra role (Authentication Administrator or Privileged Authentication Administrator).

## 5. Point the tool at it
Either:

- Sign-in screen, **Advanced**, paste the client ID, or
- Edit `%LOCALAPPDATA%\MspTapGenerator\settings.json` and set `"ClientId": "<your-client-id>"`.

The tool checks that it is a GUID and nothing else. It is not a secret.

## 6. Test
Sign in to one customer. The Dashboard should show every required scope with a tick. If one is missing, consent was not given for it. Re-send the link, or add the missing permission to the registration first.

## Common problems

| Message | Likely cause |
|---|---|
| AADSTS65001 (consent required) | Customer has not consented yet. Send the link from step 4. |
| AADSTS50011 (reply URL mismatch) | Redirect URI missing, or added under "Web" instead of "Mobile and desktop". |
| AADSTS7000218 / device code fails | "Allow public client flows" is still No. |
| AADSTS700016 (app not found in tenant) | App is single-tenant. Change to multitenant. |
| AADSTS53003 / blocked | Customer Conditional Access blocks the sign-in. Use a compliant device, or ask them to include your admin accounts. |
| Dashboard shows a scope missing | Permission not added to the registration, or customer consented before you added it. Consent again. |

## Housekeeping
- Add a second owner to the registration so it is not tied to one person.
- Review the permission list every few months. Remove the optional policy scopes if you do not use them.
- Never put a client secret or certificate on this app. The tool does not need one.
~~~~

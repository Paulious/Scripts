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
function Register-LogSecret {
    # Any registered value is replaced by [REDACTED] in everything written to the log.
    param([string]$Value)
    if ($Value -and $Value.Length -ge 6) { [void](Get-SecretRegistry).TryAdd($Value, 1) }
}
function Clear-LogSecrets { (Get-SecretRegistry).Clear() }

function Protect-LogText {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    foreach ($s in (Get-SecretRegistry).Keys) { $Text = $Text.Replace($s, '[REDACTED]') }
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
        [Parameter(Mandatory)][string]$Message
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

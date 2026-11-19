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

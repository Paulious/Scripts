# App.UI.ps1 - WPF code-behind. Dot-sourced by Start-MspTapGenerator.ps1 (which has already imported the modules
# and loaded UiTypes.cs). All state lives in $script: variables so event handlers can reach it.

$script:UiDir   = $PSScriptRoot
$script:Pool    = $null
$script:PoolHandle = $null
$script:Tasks   = [System.Collections.Generic.List[hashtable]]::new()
$script:Tick    = 0

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
    # called every 100 ms on the UI thread
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
        if ($p.Status -eq 'Enabled') {
            if ($p.IsUsableOnce) { $script:UI.OneTimeCheck.IsChecked = $true; $script:UI.OneTimeCheck.IsEnabled = $false } else { $script:UI.OneTimeCheck.IsEnabled = $true }
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
        ReplaceExisting = [bool]$UI.ReplaceCheck.IsChecked
        PolicyLength = if ($UI.ApplyLengthCheck.IsChecked) { [int]$UI.LengthSlider.Value } else { 0 }
        RestorePolicyLength = [bool]$UI.RestoreLengthCheck.IsChecked
    }
    $o.Ticket = $ticket
    $o.Key = "$($o.LifetimeMinutes)|$($o.OneTime)|$($o.StartUtc)|$($o.ReplaceExisting)"
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
        -Params @{ Users = $list; LifetimeMinutes = $o.LifetimeMinutes; OneTime = $o.OneTime; StartUtc = $o.StartUtc; ReplaceExisting = $o.ReplaceExisting } `
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
    $o = Get-GenOptions; if (-not $o) { return }
    if (-not $IsRetry -and $script:S.ValidatedKey -ne $o.Key) {
        Show-Msg 'The options changed since validation. Please Validate again.' 'Re-validate' 'OK' 'Warning'; return }
    if ($o.PolicyLength -gt 0 -and -not $script:S.Identity.CanWritePolicy) {
        Show-Msg "Changing the tenant TAP length needs the Policy.ReadWrite.AuthenticationMethod permission.`n`nSign out and sign in again with that box ticked, or untick 'Apply this length'." 'Permission needed' 'OK' 'Warning'; return }
    $id = $script:S.Identity
    $name = if ($script:S.CustomerName) { $script:S.CustomerName } else { $id.TenantName }
    $tk = if ($o.Ticket) { $o.Ticket } else { '(none entered)' }
    $text = "Ticket / change: $tk`n`nCreate $($Rows.Count) Temporary Access Pass(es) in:`n`n   $name`n   Tenant ID: $($id.TenantId)`n`nLifetime: $(Format-Lifetime $o.LifetimeMinutes)`nOne-time use: $($o.OneTime)`nActivation: $(if ($o.StartUtc) { ([datetime]$o.StartUtc).ToLocalTime().ToString('yyyy-MM-dd HH:mm') } else { 'immediately' })"
    if ($o.ReplaceExisting) { $text += "`n`nExisting TAPs for these users will be DELETED and replaced." }
    if ($o.PolicyLength -gt 0) { $text += "`n`nTenant-wide TAP length will be set to $($o.PolicyLength)$(if ($o.RestorePolicyLength) { ' and restored afterwards' } else { ' and NOT restored' })." }
    if ((Show-Msg ($text + "`n`nContinue?") 'Confirm TAP creation' 'YesNo' 'Question') -ne 'Yes') { return }

    $list = @($Rows | ForEach-Object { [pscustomobject]@{ Id = $_.Id; UserPrincipalName = $_.UserPrincipalName; DisplayName = $_.DisplayName } })
    $UI.Progress.Value = 0; $UI.ProgressText.Text = "Creating 0 / $($list.Count)"; $UI.CurrentText.Text = ''
    $script:S.LastOptions = $o

    Start-AppTask -Command 'Invoke-TapGenerationBatch' -BusyText 'Creating TAPs...' `
        -Params @{ Users = $list; LifetimeMinutes = $o.LifetimeMinutes; OneTime = $o.OneTime; StartUtc = $o.StartUtc; ReplaceExisting = $o.ReplaceExisting
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
                }
                'fail' {
                    $row = $script:Results | Where-Object UserPrincipalName -eq $d.Upn | Select-Object -First 1
                    if (-not $row) { $row = [MspTap.TapRow]::new(); $row.UserPrincipalName = $d.Upn; $script:Results.Add($row) }
                    $row.DisplayName = $d.DisplayName; $row.Tap = $null; $row.Status = 'Failed'; $row.Error = $d.Error
                    $u = $script:UserIndex[$d.Upn.ToLowerInvariant()]; if ($u) { $u.Status = 'Failed'; $u.Detail = $d.Error }
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
    $UI.LifetimeCombo.ItemsSource = @(Get-LifetimeOption)
    $UI.LifetimeCombo.SelectedItem = Get-LifetimeOption | Where-Object Minutes -eq ([int]$script:Settings.DefaultLifetimeMins) | Select-Object -First 1
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

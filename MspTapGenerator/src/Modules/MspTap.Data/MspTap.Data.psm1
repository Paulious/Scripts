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

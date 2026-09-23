<#
.SYNOPSIS
    Bulk export, build and update Group Policy Preference shared printer mappings
    (with group Item Level Targeting) from a CSV file.

.DESCRIPTION
    Group Policy Preferences keep printer mappings in an XML file in SYSVOL:
        \\<domain>\SYSVOL\<domain>\Policies\{GPO-GUID}\User\Preferences\Printers\Printers.xml

    Each printer has its own Item Level Targeting filter, and each group filter
    needs both the group name and its SID. Doing that by hand for 70 odd printers
    is painful, so this script lets you drive the whole lot from a CSV.

    There are three modes:

      Export   - Reads the printers that are in the GPO now and writes them to a CSV.
                 Use this to get your current 47 printers into Excel.

      Template - Reads the shared printers straight off a print server and writes a
                 starter CSV. Handy when the new server already has all 71 queues.

      Import   - Reads the CSV, looks up every group SID in AD, backs up the GPO,
                 writes a new Printers.xml and bumps the GPO version so clients
                 pick up the change. The CSV becomes the full list of printers in
                 the GPO, anything not in the CSV is removed from the GPO.

    CSV columns (a sheet with 'Order', 'Printer Name', 'Share Path' and 'Security Group'
    columns also works, the names are mapped for you and rows are kept in Order):
      Name      Display name of the item in GPMC. Leave blank to use the share name.
      Path      UNC path to the printer, eg \\NEWPRINT01\Finance-MFD
      Action    U (Update - default), C (Create), R (Replace) or D (Delete)
      Default   1 to set as default printer, otherwise 0
      Groups    Group(s) to target. Use DOMAIN\Group or just Group. Separate more
                than one with a semicolon, they are OR'd together.
                Leave blank for no targeting (everyone gets it).
      OldPath   Optional. The old UNC path, eg \\OLDPRINT01\Finance-MFD. If filled in,
                a Delete item is added for it (no targeting) so users lose the old
                connection when they get the new one.
      Location  Optional. Shown on the printer item.
      Comment   Optional. Shown on the printer item.

    Only needs the GroupPolicy module (RSAT GPMC). The AD PowerShell module is not needed,
    SIDs are looked up with .NET.

.PARAMETER Mode
    Export, Template or Import.

.PARAMETER GpoName
    Name of the GPO that holds the printer mappings. Needed for Export and Import.

.PARAMETER CsvPath
    CSV to write (Export / Template) or read (Import).

.PARAMETER PrintServer
    Template mode only. The print server to read shared printers from.

.PARAMETER OldPrintServer
    Template mode only. If set, the OldPath column is filled in as \\OldPrintServer\ShareName.

.PARAMETER GroupNameFormat
    Template mode only. A format string used to guess the group name from the share name,
    eg 'PRN-{0}' turns share 'Finance-MFD' into group 'PRN-Finance-MFD'.

.PARAMETER BackupPath
    Import mode only. Where the GPO backup and the old Printers.xml are saved.
    Defaults to .\GPOBackups

.PARAMETER NetBIOSDomain
    NetBIOS domain name used when a group in the CSV has no DOMAIN\ prefix.
    Defaults to the domain of the logged on user.

.PARAMETER SkipPrinterCheck
    Import mode only. Skip checking the share names actually exist on the print servers.

.EXAMPLE
    # 1. Get what is in the GPO now
    .\Update-GPOPrinterMappings.ps1 -Mode Export -GpoName 'User - Printer Mappings' -CsvPath .\printers.csv

.EXAMPLE
    # 2. Or build a starter CSV from the new server
    .\Update-GPOPrinterMappings.ps1 -Mode Template -PrintServer NEWPRINT01 -OldPrintServer OLDPRINT01 -GroupNameFormat 'PRN-{0}' -CsvPath .\printers.csv

.EXAMPLE
    # 3. Dry run. Checks everything and saves the XML it would write, but changes nothing
    .\Update-GPOPrinterMappings.ps1 -Mode Import -GpoName 'User - Printer Mappings' -CsvPath .\printers.csv -WhatIf

.EXAMPLE
    # 4. Do it for real
    .\Update-GPOPrinterMappings.ps1 -Mode Import -GpoName 'User - Printer Mappings' -CsvPath .\printers.csv

.NOTES
    Run from a domain joined machine with GPMC / RSAT installed, as someone who can edit the GPO.
    Test on a copy of the GPO first (GPMC > right click GPO > Copy) linked to a test OU.
    Only shared printers with group targeting are handled. Any other targeting type
    (computer name, IP range, OU etc) on an existing item will be reported on Export
    and is NOT carried over on Import.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
Param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Export', 'Template', 'Import')]
    [string]$Mode,

    [string]$GpoName,

    [Parameter(Mandatory = $true)]
    [string]$CsvPath,

    [string]$PrintServer,

    [string]$OldPrintServer,

    [string]$GroupNameFormat,

    [string]$BackupPath = '.\GPOBackups',

    [string]$NetBIOSDomain = $env:USERDOMAIN,

    [switch]$SkipPrinterCheck
)

$ErrorActionPreference = 'Stop'

##############################
## Constants
##############################

# These GUIDs are fixed by Microsoft for GPP printers
$PrintersClsid      = '{1F577D12-3D1B-471e-A1B7-060317597B9C}'
$SharedPrinterClsid = '{9A5E9697-9095-436d-A0EE-4D128FDFBCE5}'
$PrintersCseGuid    = '{BC75B1ED-5833-4858-9BB8-CBF0B166DF9D}'

# GPMC icon for each action
$ActionImage = @{ 'C' = '0'; 'R' = '1'; 'U' = '2'; 'D' = '3' }

##############################
## Functions
##############################

Function Get-PdcEmulator {
    # Read and write everything on the PDC so SYSVOL and AD stay in step
    [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
}

Function Get-PrintersXmlPath {
    Param($Gpo, [string]$Server)
    "\\$Server\SYSVOL\$($Gpo.DomainName)\Policies\{$($Gpo.Id)}\User\Preferences\Printers\Printers.xml"
}

Function Resolve-GroupSid {
    Param([string]$GroupName)

    If ($GroupName -notmatch '\\') {
        $GroupName = "$NetBIOSDomain\$GroupName"
    }
    Try {
        $Sid = (New-Object System.Security.Principal.NTAccount($GroupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        [pscustomobject]@{ Name = $GroupName; Sid = $Sid }
    }
    Catch {
        $null
    }
}

Function Resolve-SidName {
    # Turns a SID back into DOMAIN\Group so the export shows current names even if a group was renamed
    Param([string]$Sid)
    Try {
        (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value
    }
    Catch {
        $null
    }
}

Function Get-ShareName {
    Param([string]$UncPath)
    ($UncPath.TrimEnd('\') -split '\\')[-1]
}

Function Get-ServerName {
    Param([string]$UncPath)
    ($UncPath.TrimStart('\') -split '\\')[0]
}

Function Export-GpoPrinters {
    $Pdc = Get-PdcEmulator
    $Gpo = Get-GPO -Name $GpoName -Server $Pdc
    $XmlPath = Get-PrintersXmlPath -Gpo $Gpo -Server $Pdc

    If (-not (Test-Path $XmlPath)) {
        Throw "No printer preferences found in '$GpoName' (looked for $XmlPath)"
    }

    # Load() honours the encoding in the XML header
    $Xml = New-Object System.Xml.XmlDocument
    $Xml.Load($XmlPath)
    $Rows = @()

    ForEach ($Node in $Xml.DocumentElement.ChildNodes) {
        If ($Node.NodeType -ne 'Element') { Continue }
        $ItemName = $Node.GetAttribute('name')

        If ($Node.LocalName -ne 'SharedPrinter') {
            Write-Warning "Skipping '$ItemName' - it is a $($Node.LocalName), only shared printers are handled"
            Continue
        }

        $Props = $Node.SelectSingleNode('Properties')
        $Groups = @()
        $Filters = $Node.SelectSingleNode('Filters')
        If ($Filters) {
            ForEach ($Filter in $Filters.ChildNodes) {
                If ($Filter.NodeType -ne 'Element') { Continue }
                If ($Filter.LocalName -eq 'FilterGroup') {
                    $StoredName = $Filter.GetAttribute('name')
                    $Sid = $Filter.GetAttribute('sid')
                    If ($Filter.GetAttribute('not') -eq '1') {
                        Write-Warning "'$ItemName' has a NOT group filter on '$StoredName'. This is exported as a normal group filter, check it."
                    }
                    $CurrentName = $null
                    If ($Sid) { $CurrentName = Resolve-SidName -Sid $Sid }
                    If ($CurrentName) {
                        $Groups += $CurrentName
                    }
                    Else {
                        Write-Warning "'$ItemName': SID '$Sid' for '$StoredName' does not resolve. Using the stored name."
                        $Groups += $StoredName
                    }
                }
                Else {
                    Write-Warning "'$ItemName' has a $($Filter.LocalName) filter. This will NOT be carried over on import."
                }
            }
        }

        $Rows += [pscustomobject]@{
            Name     = $ItemName
            Path     = $Props.GetAttribute('path')
            Action   = $Props.GetAttribute('action')
            Default  = $Props.GetAttribute('default')
            Groups   = $Groups -join ';'
            OldPath  = ''
            Location = $Props.GetAttribute('location')
            Comment  = $Props.GetAttribute('comment')
        }
    }

    $Rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -WhatIf:$false
    Write-Host "Exported $($Rows.Count) printers from '$GpoName' to $CsvPath" -ForegroundColor Green
}

Function Export-PrintServerTemplate {
    If (-not $PrintServer) { Throw "-PrintServer is needed for Template mode" }

    $Printers = Get-Printer -ComputerName $PrintServer | Where-Object { $_.Shared } | Sort-Object ShareName
    $Rows = ForEach ($Printer in $Printers) {
        $Group = ''
        If ($GroupNameFormat) { $Group = $GroupNameFormat -f $Printer.ShareName }

        $OldPath = ''
        If ($OldPrintServer) { $OldPath = "\\$OldPrintServer\$($Printer.ShareName)" }

        [pscustomobject]@{
            Name     = $Printer.ShareName
            Path     = "\\$PrintServer\$($Printer.ShareName)"
            Action   = 'U'
            Default  = '0'
            Groups   = $Group
            OldPath  = $OldPath
            Location = $Printer.Location
            Comment  = $Printer.Comment
        }
    }

    $Rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -WhatIf:$false
    Write-Host "Wrote $(@($Rows).Count) shared printers from $PrintServer to $CsvPath" -ForegroundColor Green
    Write-Host "Check the Groups and OldPath columns before importing." -ForegroundColor Yellow
}

Function ConvertTo-StandardRow {
    # Lets the import take a sheet with other common column names, eg one saved straight from Excel
    # with 'Printer Name', 'Share Path' and 'Security Group' columns
    Process {
        $Aliases = @{
            'Printer Name'   = 'Name'
            'PrinterName'    = 'Name'
            'Share Path'     = 'Path'
            'SharePath'      = 'Path'
            'UNC'            = 'Path'
            'Security Group' = 'Groups'
            'SecurityGroup'  = 'Groups'
            'Group'          = 'Groups'
            'Old Path'       = 'OldPath'
        }
        $Out = [ordered]@{}
        ForEach ($Prop in $_.PSObject.Properties) {
            $Key = $Prop.Name.Trim()
            If ($Aliases.ContainsKey($Key)) { $Key = $Aliases[$Key] }
            $Out[$Key] = $Prop.Value
        }
        [pscustomobject]$Out
    }
}

Function New-SharedPrinterNode {
    Param(
        [xml]$Doc,
        [string]$Name,
        [string]$Path,
        [string]$Action,
        [string]$Default,
        [string]$Location,
        [string]$Comment,
        [object[]]$Groups
    )

    $Node = $Doc.CreateElement('SharedPrinter')
    $Node.SetAttribute('clsid', $SharedPrinterClsid)
    $Node.SetAttribute('name', $Name)
    $Node.SetAttribute('status', $Name)
    $Node.SetAttribute('image', $ActionImage[$Action])
    $Node.SetAttribute('changed', (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    $Node.SetAttribute('uid', "{$(([guid]::NewGuid()).ToString().ToUpper())}")
    $Node.SetAttribute('bypassErrors', '1')

    $Props = $Doc.CreateElement('Properties')
    $Props.SetAttribute('action', $Action)
    $Props.SetAttribute('comment', $Comment)
    $Props.SetAttribute('path', $Path)
    $Props.SetAttribute('location', $Location)
    $Props.SetAttribute('default', $Default)
    $Props.SetAttribute('skipLocal', '0')
    $Props.SetAttribute('deleteAll', '0')
    $Props.SetAttribute('persistent', '0')
    $Props.SetAttribute('deleteMaps', '0')
    $Props.SetAttribute('port', '')
    [void]$Node.AppendChild($Props)

    If ($Groups -and $Groups.Count -gt 0) {
        $Filters = $Doc.CreateElement('Filters')
        $First = $true
        ForEach ($Group in $Groups) {
            $Filter = $Doc.CreateElement('FilterGroup')
            # First filter is AND, any extra groups are OR so a member of any of them gets the printer
            If ($First) { $Filter.SetAttribute('bool', 'AND') } Else { $Filter.SetAttribute('bool', 'OR') }
            $Filter.SetAttribute('not', '0')
            $Filter.SetAttribute('name', $Group.Name)
            $Filter.SetAttribute('sid', $Group.Sid)
            $Filter.SetAttribute('userContext', '1')
            $Filter.SetAttribute('primaryGroup', '0')
            $Filter.SetAttribute('localGroup', '0')
            [void]$Filters.AppendChild($Filter)
            $First = $false
        }
        [void]$Node.AppendChild($Filters)
    }

    $Node
}

Function Import-GpoPrinters {
    $Rows = @(Import-Csv -Path $CsvPath | ConvertTo-StandardRow)
    If ($Rows.Count -eq 0) { Throw "$CsvPath has no rows" }

    # If there is an Order column, keep that order in the GPO
    If ($Rows[0].PSObject.Properties.Name -contains 'Order') {
        $Rows = @($Rows | Sort-Object { [int]("0" + "$($_.Order)".Trim()) })
    }

    $Pdc = Get-PdcEmulator
    $Gpo = Get-GPO -Name $GpoName -Server $Pdc
    $XmlPath = Get-PrintersXmlPath -Gpo $Gpo -Server $Pdc
    Write-Host "GPO: $($Gpo.DisplayName) {$($Gpo.Id)} on $Pdc"

    ##
    ## Check every row before touching anything
    ##
    $Problems = @()
    $SidCache = @{}
    $Items = @()

    $RowNo = 1   # header is row 1, so this matches the row number in Excel
    ForEach ($Row in $Rows) {
        $RowNo++

        $Path = "$($Row.Path)".Trim()
        If ($Path -notmatch '^\\\\[^\\]+\\[^\\]+$') {
            $Problems += "Row ${RowNo}: Path '$Path' is not a valid \\server\share path"
            Continue
        }

        $Action = "$($Row.Action)".Trim().ToUpper()
        If (-not $Action) { $Action = 'U' }
        If (-not $ActionImage.ContainsKey($Action)) {
            $Problems += "Row ${RowNo}: Action '$Action' should be U, C, R or D"
            Continue
        }

        $Default = "$($Row.Default)".Trim()
        If ($Default -ne '1') { $Default = '0' }

        $Name = "$($Row.Name)".Trim()
        If (-not $Name) { $Name = Get-ShareName $Path }

        $Groups = @()
        ForEach ($GroupName in ("$($Row.Groups)" -split ';')) {
            $GroupName = $GroupName.Trim()
            If (-not $GroupName) { Continue }
            If (-not $SidCache.ContainsKey($GroupName)) {
                $SidCache[$GroupName] = Resolve-GroupSid -GroupName $GroupName
            }
            If ($SidCache[$GroupName]) {
                $Groups += $SidCache[$GroupName]
            }
            Else {
                $Problems += "Row ${RowNo}: Group '$GroupName' for '$Name' was not found in AD"
            }
        }
        If ($Groups.Count -eq 0 -and $Action -ne 'D') {
            Write-Warning "Row ${RowNo}: '$Name' has no group targeting, every user in scope of the GPO will get it"
        }

        $OldPath = "$($Row.OldPath)".Trim()
        If ($OldPath -and $OldPath -notmatch '^\\\\[^\\]+\\[^\\]+$') {
            $Problems += "Row ${RowNo}: OldPath '$OldPath' is not a valid \\server\share path"
            Continue
        }

        $Items += [pscustomobject]@{
            Name     = $Name
            Path     = $Path
            Action   = $Action
            Default  = $Default
            Location = "$($Row.Location)"
            Comment  = "$($Row.Comment)"
            Groups   = $Groups
            OldPath  = $OldPath
        }
    }

    # Catch copy and paste mistakes
    $Items | Group-Object Path | Where-Object { $_.Count -gt 1 } | ForEach-Object {
        $Problems += "Path $($_.Name) is in the CSV $($_.Count) times"
    }
    $DefaultCount = @($Items | Where-Object { $_.Default -eq '1' }).Count
    If ($DefaultCount -gt 0) {
        Write-Warning "$DefaultCount printer(s) are set as default. If a user gets more than one, the last one processed wins."
    }

    # Check the shares exist on the print server(s)
    If (-not $SkipPrinterCheck) {
        $Servers = $Items | Where-Object { $_.Action -ne 'D' } | ForEach-Object { Get-ServerName $_.Path } | Sort-Object -Unique
        ForEach ($Server in $Servers) {
            Try {
                $Shares = Get-Printer -ComputerName $Server | Where-Object { $_.Shared } | Select-Object -ExpandProperty ShareName
                $Items | Where-Object { $_.Action -ne 'D' -and (Get-ServerName $_.Path) -eq $Server } | ForEach-Object {
                    If ($Shares -notcontains (Get-ShareName $_.Path)) {
                        $Problems += "Share $($_.Path) does not exist on $Server"
                    }
                }
            }
            Catch {
                Write-Warning "Could not list printers on $Server ($($_.Exception.Message)). Use -SkipPrinterCheck to skip this."
            }
        }
    }

    If ($Problems.Count -gt 0) {
        $Problems | ForEach-Object { Write-Host $_ -ForegroundColor Red }
        Throw "Found $($Problems.Count) problem(s) in the CSV. Nothing has been changed."
    }

    ##
    ## Build the new Printers.xml
    ##
    [xml]$Doc = New-Object System.Xml.XmlDocument
    [void]$Doc.AppendChild($Doc.CreateXmlDeclaration('1.0', 'utf-8', $null))
    $Root = $Doc.CreateElement('Printers')
    $Root.SetAttribute('clsid', $PrintersClsid)
    [void]$Doc.AppendChild($Root)

    # Deletes for the old server go first so the old connection is gone before the new one is added
    $OldPaths = $Items | Where-Object { $_.OldPath } | Select-Object -ExpandProperty OldPath | Sort-Object -Unique
    ForEach ($OldPath in $OldPaths) {
        $Node = New-SharedPrinterNode -Doc $Doc -Name "Remove $(Get-ShareName $OldPath)" -Path $OldPath -Action 'D' -Default '0' -Location '' -Comment 'Old print server' -Groups @()
        [void]$Root.AppendChild($Node)
    }

    ForEach ($Item in $Items) {
        $Node = New-SharedPrinterNode -Doc $Doc -Name $Item.Name -Path $Item.Path -Action $Item.Action -Default $Item.Default -Location $Item.Location -Comment $Item.Comment -Groups $Item.Groups
        [void]$Root.AppendChild($Node)
    }

    $Summary = "$(@($Items).Count) printer item(s), $(@($OldPaths).Count) old server delete item(s), $($SidCache.Count) group(s)"

    If (-not $PSCmdlet.ShouldProcess("$GpoName", "Replace printer preferences with $Summary")) {
        $Preview = Join-Path $env:TEMP "$($Gpo.Id)-Printers-preview.xml"
        $Doc.Save($Preview)
        Write-Host "Everything checks out. Preview XML saved to $Preview" -ForegroundColor Green
        Return
    }

    ##
    ## Back up, then write
    ##
    If (-not (Test-Path $BackupPath)) { New-Item -Path $BackupPath -ItemType Directory | Out-Null }
    $BackupPath = (Resolve-Path $BackupPath).Path
    $Backup = Backup-GPO -Guid $Gpo.Id -Path $BackupPath -Server $Pdc -Comment "Before printer update $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
    Write-Host "GPO backed up to $BackupPath (backup id $($Backup.Id))"

    If (Test-Path $XmlPath) {
        Copy-Item -Path $XmlPath -Destination (Join-Path $BackupPath "Printers-$(Get-Date -Format 'yyyyMMdd-HHmmss').xml")
    }
    Else {
        New-Item -Path (Split-Path $XmlPath) -ItemType Directory -Force | Out-Null
    }

    $Doc.Save($XmlPath)
    Write-Host "Wrote $XmlPath"

    # Bump the user version, otherwise clients think nothing has changed and skip the GPO.
    # The top 16 bits of the version number are the user side, the bottom 16 the computer side.
    $GpoAdsi = [ADSI]"LDAP://$Pdc/$($Gpo.Path)"
    $OldVersion = [int]$GpoAdsi.versionNumber.Value
    $NewVersion = $OldVersion + 65536

    $GptIni = "\\$Pdc\SYSVOL\$($Gpo.DomainName)\Policies\{$($Gpo.Id)}\GPT.INI"
    $IniText = Get-Content -Path $GptIni -Raw
    If ($IniText -match '(?m)^Version=\d+') {
        $IniText = $IniText -replace '(?m)^Version=\d+', "Version=$NewVersion"
    }
    Else {
        $IniText = $IniText.TrimEnd() + "`r`nVersion=$NewVersion`r`n"
    }
    [System.IO.File]::WriteAllText($GptIni, $IniText, [System.Text.Encoding]::ASCII)

    $GpoAdsi.Put('versionNumber', $NewVersion)
    $GpoAdsi.SetInfo()
    Write-Host "GPO version $OldVersion -> $NewVersion"

    # If the GPO never had printers in it, clients won't know to run the printer extension
    If ("$($GpoAdsi.gPCUserExtensionNames)" -notmatch [regex]::Escape($PrintersCseGuid)) {
        Write-Warning "The GPO is not registered for printer preferences. Open it in GPMC, add and then delete any dummy printer item, so GPMC registers the extension."
    }

    Write-Host "Done. $Summary" -ForegroundColor Green
}

##############################
## Main
##############################

Import-Module GroupPolicy

Switch ($Mode) {
    'Export' {
        If (-not $GpoName) { Throw "-GpoName is needed for Export mode" }
        Export-GpoPrinters
    }
    'Template' {
        Export-PrintServerTemplate
    }
    'Import' {
        If (-not $GpoName) { Throw "-GpoName is needed for Import mode" }
        Import-GpoPrinters
    }
}

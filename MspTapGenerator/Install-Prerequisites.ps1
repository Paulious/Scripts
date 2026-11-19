#Requires -Version 7.2
<#
.SYNOPSIS  Installs the PowerShell modules MSP TAP Generator needs (per-user by default, no admin rights).
.PARAMETER Scope  CurrentUser (default) or AllUsers (needs an elevated prompt).
#>
[CmdletBinding()]
param(
    [ValidateSet('CurrentUser', 'AllUsers')][string]$Scope = 'CurrentUser',
    [string]$GraphVersion,                 # force a specific Graph SDK version, e.g. 2.35.1
    [switch]$RemoveOtherGraphVersions      # uninstall other versions of the five Graph modules this app uses (affects other scripts!)
)

$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'Windows only.' }

$graph = 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Users', 'Microsoft.Graph.Groups',
         'Microsoft.Graph.Identity.SignIns', 'Microsoft.Graph.Identity.DirectoryManagement'

# All Graph modules MUST be the same version, or PowerShell fails with "Assembly with same name is already loaded".
if (-not $GraphVersion) {
    $sets = foreach ($n in $graph) { , @(Get-Module -ListAvailable -Name $n | ForEach-Object { $_.Version.ToString() } | Select-Object -Unique) }
    $common = $sets[0]; foreach ($set in $sets[1..($sets.Count - 1)]) { $common = @($common | Where-Object { $_ -in $set }) }
    $GraphVersion = $common | Where-Object { [version]$_ -ge [version]'2.10.0' } | Sort-Object { [version]$_ } -Descending | Select-Object -First 1
    if ($GraphVersion) { Write-Host "All five Graph modules already share version $GraphVersion - using it." -ForegroundColor Green }
    else {
        Write-Host 'No single Graph SDK version covers all five modules. Looking up the newest on PSGallery...' -ForegroundColor Yellow
        $GraphVersion = (Find-Module -Name Microsoft.Graph.Authentication -Repository PSGallery).Version.ToString()
    }
}
$modules = @($graph | ForEach-Object { @{ Name = $_; Exact = $GraphVersion } }) + @(@{ Name = 'ImportExcel'; Min = '7.8.0' })
if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
    Write-Host 'PSGallery is not trusted; you will be asked to confirm each install.' -ForegroundColor Yellow
}
foreach ($m in $modules) {
    $have = Get-Module -ListAvailable -Name $m.Name | Sort-Object Version -Descending
    if ($m.Exact) {
        if ($have | Where-Object { $_.Version -eq [version]$m.Exact }) { Write-Host "OK       $($m.Name) $($m.Exact)"; continue }
        Write-Host "Installing $($m.Name) $($m.Exact)..." -ForegroundColor Cyan
        Install-Module -Name $m.Name -RequiredVersion $m.Exact -Scope $Scope -Repository PSGallery -AllowClobber -Force
    }
    else {
        if ($have -and $have[0].Version -ge [version]$m.Min) { Write-Host "OK       $($m.Name) $($have[0].Version)"; continue }
        Write-Host "Installing $($m.Name) (>= $($m.Min))..." -ForegroundColor Cyan
        Install-Module -Name $m.Name -MinimumVersion $m.Min -Scope $Scope -Repository PSGallery -AllowClobber -Force
    }
}
if ($RemoveOtherGraphVersions) {
    foreach ($n in $graph) {
        Get-InstalledModule -Name $n -AllVersions -ErrorAction SilentlyContinue | Where-Object { $_.Version -ne [version]$GraphVersion } |
            ForEach-Object { Write-Host "Removing $($_.Name) $($_.Version)" -ForegroundColor Yellow; Uninstall-Module -Name $_.Name -RequiredVersion $_.Version -Force }
    }
}
Write-Host "`nAll prerequisites present. Start the app with: pwsh -STA -File .\Start-MspTapGenerator.ps1" -ForegroundColor Green
Write-Host "Graph SDK version used by the app: $GraphVersion. Start the app from a NEW pwsh window (a window that already loaded another Graph version will conflict)."

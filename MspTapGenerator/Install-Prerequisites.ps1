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

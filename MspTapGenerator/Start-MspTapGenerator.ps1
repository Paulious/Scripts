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

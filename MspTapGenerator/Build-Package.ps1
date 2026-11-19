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
        $r = Invoke-ScriptAnalyzer -Path $root -Recurse -Severity Error,Warning -ExcludeRule PSAvoidUsingWriteHost,PSUseShouldProcessForStateChangingFunctions,PSUseApprovedVerbs,PSAvoidGlobalVars
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

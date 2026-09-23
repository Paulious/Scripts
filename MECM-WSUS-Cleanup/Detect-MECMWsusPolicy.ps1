<#
.SYNOPSIS
    Intune detection script - finds WSUS settings the MECM client has left behind in local policy.

.DESCRIPTION
    Pair with Remove-MECMWsusPolicy.ps1 as an Intune remediation.

    Exit 1 (needs fixing) only when BOTH are true:
      - the MECM Software Updates agent is OFF on this device, and
      - WSUS / scan source settings are still in local policy (Registry.pol) or the registry.

    If the agent is still ON, the device exits 0. MECM is still managing updates there,
    so the settings are expected and the clean-up would not stick.

.NOTES
    Read only - changes nothing. Run as SYSTEM, 64-bit.
#>

##############################
## Variables
##############################

$PolFile      = "$env:windir\System32\GroupPolicy\Machine\Registry.pol"

$WUKey        = 'Software\Policies\Microsoft\Windows\WindowsUpdate'
$AUKey        = 'Software\Policies\Microsoft\Windows\WindowsUpdate\AU'

# Keep this list the same as in Remove-MECMWsusPolicy.ps1
$TargetValues = @{
    $WUKey = @(
        'WUServer'
        'WUStatusServer'
        'UpdateServiceUrlAlternate'
        'FillEmptyContentUrls'
        'DoNotEnforceEnterpriseTLSCertPinningForUpdateDetection'
        'SetProxyBehaviorForUpdateDetection'
        'AcceptTrustedPublisherCerts'
        'SetPolicyDrivenUpdateSourceForFeatureUpdates'
        'SetPolicyDrivenUpdateSourceForQualityUpdates'
        'SetPolicyDrivenUpdateSourceForDriverUpdates'
        'SetPolicyDrivenUpdateSourceForOtherUpdates'
    )
    $AUKey = @(
        'UseWUServer'
        'UseUpdateClassPolicySource'
    )
}

##############################
## Functions
##############################

Function Test-TargetValue {
    Param([string]$Key, [string]$ValueName)
    $Name = $ValueName -replace '^\*\*del\.', ''
    foreach ($TargetKey in $TargetValues.Keys) {
        if ($Key -ieq $TargetKey -and ($TargetValues[$TargetKey] -icontains $Name)) {
            return $true
        }
    }
    return $false
}

Function Get-PolEntryNames {
    # Returns "key\value" for each entry in a Registry.pol file.
    Param([byte[]]$Bytes)
    if ($Bytes.Length -lt 8 -or [BitConverter]::ToUInt32($Bytes, 0) -ne 0x67655250) {
        throw 'Registry.pol does not have a valid PReg header.'
    }
    $Pos = 8
    while ($Pos -lt $Bytes.Length) {
        $Parts = @()
        $Pos += 2                                   # [
        foreach ($i in 1..2) {                      # key, then value name
            $Start = $Pos
            while ($Pos + 1 -lt $Bytes.Length -and -not ($Bytes[$Pos] -eq 0 -and $Bytes[$Pos + 1] -eq 0)) { $Pos += 2 }
            $Parts += [Text.Encoding]::Unicode.GetString($Bytes, $Start, $Pos - $Start)
            $Pos += 4                               # null + ;
        }
        $Pos += 6                                   # type + ;
        $Size = [BitConverter]::ToUInt32($Bytes, $Pos)
        $Pos += 6 + $Size + 2                       # size + ; + data + ]
        [pscustomobject]@{ Key = $Parts[0]; ValueName = $Parts[1] }
    }
}

##############################
## Main
##############################

try {
    # Is MECM still managing updates here?
    $Config = Get-CimInstance -Namespace 'root\ccm\Policy\Machine\ActualConfig' -ClassName 'CCM_SoftwareUpdatesClientConfig' -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $Config) {
        Write-Output 'No MECM Software Updates policy found - skipping.'
        exit 0
    }
    if ([bool]$Config.Enabled) {
        Write-Output 'MECM Software Updates agent is ON - WSUS settings expected, skipping.'
        exit 0
    }

    $Found = @()

    if (Test-Path $PolFile) {
        $Found += Get-PolEntryNames -Bytes ([IO.File]::ReadAllBytes($PolFile)) |
            Where-Object { Test-TargetValue -Key $_.Key -ValueName $_.ValueName } |
            ForEach-Object { "Registry.pol: $($_.ValueName)" }
    }

    foreach ($Key in $TargetValues.Keys) {
        $Path = "HKLM:\$Key"
        if (-not (Test-Path $Path)) { continue }
        $Props = Get-ItemProperty -Path $Path
        foreach ($Name in $TargetValues[$Key]) {
            if ($null -ne $Props.PSObject.Properties[$Name]) { $Found += "Registry: $Name" }
        }
    }

    if ($Found.Count -gt 0) {
        Write-Output "Leftover WSUS settings found: $($Found -join ', ')"
        exit 1
    }

    Write-Output 'No leftover WSUS settings.'
    exit 0
} catch {
    Write-Output "Detection error: $($_.Exception.Message)"
    exit 1
}

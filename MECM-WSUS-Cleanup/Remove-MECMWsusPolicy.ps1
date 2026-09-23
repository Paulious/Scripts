<#
.SYNOPSIS
    Removes the WSUS settings the MECM client leaves behind in local policy.

.DESCRIPTION
    During the build the device gets the Default Client Settings (Software Updates = Yes),
    so the MECM client writes the WSUS server and scan source settings into local policy.
    When the device later gets the co-managed client settings (Software Updates = No) the
    agent turns off but the settings stay behind and point Windows Update at WSUS.

    This script:
      1. Checks the MECM Software Updates agent is OFF. If it is still on, nothing is changed,
         because the client would just write the settings back.
      2. Backs up the local policy file (Registry.pol) and the Windows Update policy key.
      3. Removes only the WSUS / scan source entries from Registry.pol, so gpupdate cannot put them back.
      4. Removes the same values from the registry and clears the Windows Update policy cache.
      5. Runs gpupdate and restarts the Windows Update service.

    Anything else in local policy, or under the Windows Update key, is left alone.

    Can be used as an Intune remediation script or as a task sequence step. Must run as SYSTEM / admin.

.PARAMETER SkipAgentCheck
    Skip the check that the MECM Software Updates agent is off. Only use this for testing,
    or on a device that has no MECM client.

.EXAMPLE
    .\Remove-MECMWsusPolicy.ps1 -WhatIf
    Shows what would be removed without changing anything.

.NOTES
    Log:     C:\Windows\Temp\Remove-MECMWsusPolicy.log
    Backups: C:\ProgramData\MECMWsusCleanup\Backup\<date-time>\
    Exit 0 = cleaned or nothing to do. Exit 1 = error.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
Param(
    [switch]$SkipAgentCheck
)

##############################
## Variables
##############################

$LogFile      = "$env:windir\Temp\Remove-MECMWsusPolicy.log"
$BackupRoot   = "$env:ProgramData\MECMWsusCleanup\Backup\$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$PolFile      = "$env:windir\System32\GroupPolicy\Machine\Registry.pol"
$GptIni       = "$env:windir\System32\GroupPolicy\gpt.ini"

$WUKey        = 'Software\Policies\Microsoft\Windows\WindowsUpdate'
$AUKey        = 'Software\Policies\Microsoft\Windows\WindowsUpdate\AU'

# Values the MECM client writes for WSUS. Nothing else is touched.
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

$GPCacheKeys = @(
    'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\GPCache\CacheSet001\WindowsUpdate'
    'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\GPCache\CacheSet002\WindowsUpdate'
)

##############################
## Functions
##############################

Function Write-Log {
    Param([string]$Message)
    $Line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $Message"
    Write-Output $Line
    Add-Content -Path $LogFile -Value $Line -ErrorAction SilentlyContinue
}

Function Test-TargetValue {
    # True if this key / value name is one we want to remove.
    # Also matches "**del.<name>" entries, which are delete markers for the same value.
    Param([string]$Key, [string]$ValueName)
    $Name = $ValueName -replace '^\*\*del\.', ''
    foreach ($TargetKey in $TargetValues.Keys) {
        if ($Key -ieq $TargetKey -and ($TargetValues[$TargetKey] -icontains $Name)) {
            return $true
        }
    }
    return $false
}

Function Read-PolString {
    # Reads a null-terminated UTF-16LE string and moves past the null.
    Param([byte[]]$Bytes, [ref]$Pos)
    $Start = $Pos.Value
    while ($Pos.Value + 1 -lt $Bytes.Length -and -not ($Bytes[$Pos.Value] -eq 0 -and $Bytes[$Pos.Value + 1] -eq 0)) {
        $Pos.Value += 2
    }
    $Text = [Text.Encoding]::Unicode.GetString($Bytes, $Start, $Pos.Value - $Start)
    $Pos.Value += 2
    return $Text
}

Function Skip-PolChar {
    # Checks the next UTF-16 character is the expected separator and moves past it.
    Param([byte[]]$Bytes, [ref]$Pos, [char]$Expected)
    if ($Pos.Value + 1 -ge $Bytes.Length -or [BitConverter]::ToChar($Bytes, $Pos.Value) -ne $Expected) {
        throw "Registry.pol is not in the expected format (expected '$Expected' at byte $($Pos.Value))."
    }
    $Pos.Value += 2
}

Function Read-PolEntries {
    # Reads a Registry.pol file and returns each entry with its key, value name and raw bytes.
    # Format: "PReg" + version (8 bytes), then entries of [key;value;type;size;data] in UTF-16LE.
    Param([byte[]]$Bytes)

    if ($Bytes.Length -lt 8 -or [BitConverter]::ToUInt32($Bytes, 0) -ne 0x67655250) {
        throw 'Registry.pol does not have a valid PReg header.'
    }

    $Entries = New-Object System.Collections.Generic.List[object]
    $Pos = [ref]8

    while ($Pos.Value -lt $Bytes.Length) {
        $EntryStart = $Pos.Value
        Skip-PolChar -Bytes $Bytes -Pos $Pos -Expected '['
        $Key = Read-PolString -Bytes $Bytes -Pos $Pos
        Skip-PolChar -Bytes $Bytes -Pos $Pos -Expected ';'
        $ValueName = Read-PolString -Bytes $Bytes -Pos $Pos
        Skip-PolChar -Bytes $Bytes -Pos $Pos -Expected ';'
        $Pos.Value += 4          # type
        Skip-PolChar -Bytes $Bytes -Pos $Pos -Expected ';'
        $Size = [BitConverter]::ToUInt32($Bytes, $Pos.Value)
        $Pos.Value += 4
        Skip-PolChar -Bytes $Bytes -Pos $Pos -Expected ';'
        $Pos.Value += $Size      # data
        Skip-PolChar -Bytes $Bytes -Pos $Pos -Expected ']'

        $Raw = New-Object byte[] ($Pos.Value - $EntryStart)
        [Array]::Copy($Bytes, $EntryStart, $Raw, 0, $Raw.Length)
        $Entries.Add([pscustomobject]@{ Key = $Key; ValueName = $ValueName; Raw = $Raw })
    }
    return ,$Entries
}

Function Get-SoftwareUpdatesAgentEnabled {
    # Returns $true / $false from the policy the client has actually received, or $null if there is no MECM client.
    try {
        $Config = Get-CimInstance -Namespace 'root\ccm\Policy\Machine\ActualConfig' -ClassName 'CCM_SoftwareUpdatesClientConfig' -ErrorAction Stop |
            Select-Object -First 1
        if ($null -eq $Config) { return $null }
        return [bool]$Config.Enabled
    } catch {
        return $null
    }
}

Function Update-GptIniVersion {
    # Bumps the computer part of the local GPO version so Group Policy sees the change.
    if (-not (Test-Path $GptIni)) { return }
    $Content = Get-Content -Path $GptIni
    $Updated = foreach ($Line in $Content) {
        if ($Line -match '^\s*Version\s*=\s*(\d+)\s*$') {
            $Version  = [uint32]$Matches[1]
            $User     = $Version -shr 16
            $Computer = (($Version -band 0xFFFF) + 1) -band 0xFFFF
            "Version=$(($User -shl 16) -bor $Computer)"
        } else {
            $Line
        }
    }
    Set-Content -Path $GptIni -Value $Updated -Encoding Ascii
}

##############################
## Main
##############################

try {
    Write-Log '----- Starting MECM WSUS policy clean-up -----'

    # 1. Safety check - only clean up if MECM is not managing updates on this device.
    if (-not $SkipAgentCheck) {
        $AgentEnabled = Get-SoftwareUpdatesAgentEnabled
        if ($null -eq $AgentEnabled) {
            Write-Log 'Could not read the MECM Software Updates agent setting (no client, or no policy yet). Nothing changed.'
            exit 0
        }
        if ($AgentEnabled) {
            Write-Log 'MECM Software Updates agent is ON for this device. The client would write the settings back, so nothing changed.'
            exit 0
        }
        Write-Log 'MECM Software Updates agent is OFF. Carrying on.'
    }

    # 2. Work out what needs removing.
    $PolEntries  = $null
    $PolToRemove = @()
    if (Test-Path $PolFile) {
        $PolEntries  = Read-PolEntries -Bytes ([IO.File]::ReadAllBytes($PolFile))
        $PolToRemove = @($PolEntries | Where-Object { Test-TargetValue -Key $_.Key -ValueName $_.ValueName })
    }

    $RegToRemove = @()
    foreach ($Key in $TargetValues.Keys) {
        $Path = "HKLM:\$Key"
        if (-not (Test-Path $Path)) { continue }
        $Props = Get-ItemProperty -Path $Path
        foreach ($Name in $TargetValues[$Key]) {
            if ($null -ne $Props.PSObject.Properties[$Name]) {
                $RegToRemove += [pscustomobject]@{ Path = $Path; Name = $Name }
            }
        }
    }

    if ($PolToRemove.Count -eq 0 -and $RegToRemove.Count -eq 0) {
        Write-Log 'No leftover WSUS settings found. Nothing to do.'
        exit 0
    }

    foreach ($Entry in $PolToRemove) { Write-Log "Found in Registry.pol: $($Entry.Key)\$($Entry.ValueName)" }
    foreach ($Item in $RegToRemove)  { Write-Log "Found in registry:     $($Item.Path)\$($Item.Name)" }

    if (-not $PSCmdlet.ShouldProcess('local policy and registry', 'Remove leftover WSUS settings')) {
        Write-Log 'WhatIf - nothing changed.'
        exit 0
    }

    # 3. Back up before changing anything.
    New-Item -Path $BackupRoot -ItemType Directory -Force | Out-Null
    if (Test-Path $PolFile) { Copy-Item -Path $PolFile -Destination "$BackupRoot\Registry.pol" -Force }
    if (Test-Path $GptIni)  { Copy-Item -Path $GptIni  -Destination "$BackupRoot\gpt.ini" -Force }
    & reg.exe export "HKLM\$WUKey" "$BackupRoot\WindowsUpdatePolicy.reg" /y | Out-Null
    Write-Log "Backup saved to $BackupRoot"

    # 4. Rewrite Registry.pol without the WSUS entries.
    if ($PolToRemove.Count -gt 0) {
        $Stream = New-Object IO.MemoryStream
        $Header = [IO.File]::ReadAllBytes($PolFile)[0..7]
        $Stream.Write($Header, 0, 8)
        foreach ($Entry in $PolEntries) {
            if (-not (Test-TargetValue -Key $Entry.Key -ValueName $Entry.ValueName)) {
                $Stream.Write($Entry.Raw, 0, $Entry.Raw.Length)
            }
        }
        [IO.File]::WriteAllBytes($PolFile, $Stream.ToArray())
        $Stream.Dispose()
        Update-GptIniVersion
        Write-Log "Removed $($PolToRemove.Count) entries from Registry.pol."
    }

    # 5. Remove the values from the registry.
    foreach ($Item in $RegToRemove) {
        Remove-ItemProperty -Path $Item.Path -Name $Item.Name -Force -ErrorAction Stop
    }
    Write-Log "Removed $($RegToRemove.Count) values from the registry."

    # 6. Clear the Windows Update policy cache so it re-reads policy.
    foreach ($CacheKey in $GPCacheKeys) {
        if (Test-Path $CacheKey) {
            Remove-Item -Path $CacheKey -Recurse -Force
            Write-Log "Cleared cache: $CacheKey"
        }
    }

    # 7. Refresh policy and restart Windows Update.
    & gpupdate.exe /target:computer /force | Out-Null
    Write-Log 'gpupdate finished.'
    Restart-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Write-Log 'Windows Update service restarted.'

    Write-Log '----- Clean-up complete -----'
    exit 0
} catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    exit 1
}

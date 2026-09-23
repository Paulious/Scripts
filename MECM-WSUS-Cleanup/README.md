# MECM WSUS clean-up

## The problem

When a machine is built, the MECM client picks up the Default Client Settings. Those have Software Updates switched on, so the client writes the WSUS server settings into local policy.

Later the machine moves into the co-managed collection, where Software Updates is switched off. MECM stops managing updates, but it never removes the WSUS settings it wrote. Windows keeps reading them, so updates still point at WSUS instead of Intune.

## What the scripts do

| Script | What it does |
|---|---|
| `Detect-MECMWsusPolicy.ps1` | Looks for the leftover settings. Read only, changes nothing. |
| `Remove-MECMWsusPolicy.ps1` | Removes the leftover settings. |

The clean-up script:

1. **Checks MECM Software Updates is switched off on the machine.** If it's still on, the script stops and changes nothing, because MECM would just put the settings back.
2. **Makes a backup** of the local policy file and the Windows Update registry key.
3. **Removes the WSUS entries from the local policy file** (`Registry.pol`). This is why your first script didn't stick: it cleared the registry, but the policy file still held the settings and put them back.
4. **Removes the same values from the registry** and clears the Windows Update policy cache.
5. **Runs gpupdate** and restarts the Windows Update service.

It only removes the WSUS settings. Anything else in local policy or under the Windows Update key is left alone.

### Settings it removes

Under `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`:
- WUServer, WUStatusServer, UpdateServiceUrlAlternate, FillEmptyContentUrls
- DoNotEnforceEnterpriseTLSCertPinningForUpdateDetection, SetProxyBehaviorForUpdateDetection
- AcceptTrustedPublisherCerts
- SetPolicyDrivenUpdateSourceForFeatureUpdates / QualityUpdates / DriverUpdates / OtherUpdates

Under `...\WindowsUpdate\AU`:
- UseWUServer, UseUpdateClassPolicySource

## Test on one machine first

Run PowerShell as admin on a machine that has the problem:

```powershell
.\Detect-MECMWsusPolicy.ps1            # should say leftover settings found
.\Remove-MECMWsusPolicy.ps1 -WhatIf    # shows what it would remove, changes nothing
.\Remove-MECMWsusPolicy.ps1            # does the clean-up
.\Detect-MECMWsusPolicy.ps1            # should now say no leftover settings
gpresult /h C:\Temp\gp.html            # the WSUS section should be gone
```

Then leave it a day and run the detection again. If the settings come back, something else is writing them, so don't roll it out yet.

## Using it in Intune

**Devices > Scripts and remediations > Create**

- Detection script: `Detect-MECMWsusPolicy.ps1`
- Remediation script: `Remove-MECMWsusPolicy.ps1`
- Run this script using the logged-on credentials: **No**
- Enforce script signature check: **No** (unless you sign your scripts)
- Run script in 64-bit PowerShell: **Yes**
- Assign to a pilot group first, then the co-managed devices. Daily is fine.

Machines where MECM still manages updates are skipped by the detection, so it's safe if the group is wider than it needs to be.

## Using it in the task sequence

Add a **Run PowerShell Script** step at the end of the build and tick **Continue on error**.

This only cleans up if Software Updates is **off** for the machine during the build. If the build still gets Default Client Settings (Software Updates on), the script sees that, writes it in the log and does nothing. That's by design, because MECM would put the settings straight back. In that case the Intune remediation catches the machine later, once it's in the co-managed collection.

## Logs and backups

- Log: `C:\Windows\Temp\Remove-MECMWsusPolicy.log`
- Backups: `C:\ProgramData\MECMWsusCleanup\Backup\<date-time>\`

## How to undo it

From the backup folder, as admin:

```powershell
Copy-Item .\Registry.pol C:\Windows\System32\GroupPolicy\Machine\Registry.pol -Force
Copy-Item .\gpt.ini      C:\Windows\System32\GroupPolicy\gpt.ini -Force
reg import .\WindowsUpdatePolicy.reg
gpupdate /target:computer /force
Restart-Service wuauserv -Force
```

## Before rolling out

- Raise a change request. It changes where co-managed machines get their updates from.
- Check the Intune update rings are assigned to these machines, so they're covered once WSUS is removed.
- Check the co-managed collection doesn't overlap with collections whose client settings have a higher priority and Software Updates switched on (for example the FIDS/AOS settings at priority 6 and 7).

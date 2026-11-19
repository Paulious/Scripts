# MSP TAP Generator

A Windows desktop tool for MSPs. It creates Microsoft Entra **Temporary Access Passes (TAPs)** in bulk, so you can get a batch of devices through Windows Autopilot without chasing passwords.

PowerShell 7 + WPF. Uses the Microsoft Graph PowerShell SDK. Works across many customer tenants. Stores no credentials.

> **Status:** written and reviewed by hand, but I could not run it on Windows when I built it (the build environment was Linux with no PowerShell). Treat the first run as a pilot: try it against a test tenant with 2 or 3 users before a real batch. See "Pilot checklist" at the bottom.

## What it does

- Sign in per customer: interactive browser or device code. Pick the tenant first.
- Load users from **CSV**, **XLSX** (pick the sheet and map the columns) or **Entra** (search, department, job title, group).
- Check everything before it creates anything: permissions, TAP policy, user exists, account enabled, not a guest.
- Create TAPs with a lifetime, one-time use, and optional delayed start.
- Progress with counts, current user and ETA. Retry failures. Export failures.
- Results grid with the TAP masked. Show/hide, copy, export to `TAPs_YYYYMMDD_HHMMSS.xlsx`.
- Dark and light theme. The customer name and tenant ID are shown in the banner at all times.

## One thing you need to know about "password length"

Microsoft Graph cannot set the length of a single TAP. Length is a **tenant-wide policy setting** (`defaultLength`, 8-48).

So the length slider works like this:

- By default it is locked and shows the tenant's current length (read from the policy).
- If you tick **Apply this length to the tenant TAP policy**, the tool changes the policy before the batch and (by default) puts the old value back afterwards.
- That needs one extra permission, `Policy.ReadWrite.AuthenticationMethod`, which you opt into on the sign-in screen. It changes a setting for the whole tenant, so you get a confirmation first.
- The `TAPLength` column in the export is the real length of each pass that came back, not the slider value.

## Folder structure

```
MspTapGenerator/
  Start-MspTapGenerator.ps1      entry point (checks modules, loads UI)
  Install-Prerequisites.ps1      installs Graph SDK + ImportExcel
  Build-Package.ps1              lint, test, sign (optional), zip
  src/
    Modules/
      MspTap.Core/               logging + TAP scrubbing, settings, tenant profiles, retry/back-off
      MspTap.Data/               CSV / XLSX import, XLSX export
      MspTap.Graph/              sign-in, policy, lookup, validation, TAP creation, batch workers
    UI/
      MainWindow.xaml            layout
      Theme.Dark.xaml / Theme.Light.xaml
      UiTypes.cs                 row classes for the grids (TAP held as SecureString)
      App.UI.ps1                 code-behind, task runner, handlers
  tests/MspTap.Tests.ps1         Pester 5 tests (no Graph needed)
  samples/                       example CSV files
  docs/                          SECURITY.md, GRAPH-PERMISSIONS.md, ERROR-HANDLING.md
```

## Requirements

- Windows 10/11 or Server 2019+ (WPF)
- PowerShell **7.2 or later** (`winget install Microsoft.PowerShell`)
- Modules: `Microsoft.Graph.Authentication`, `.Users`, `.Groups`, `.Identity.SignIns`, `.Identity.DirectoryManagement` (2.10.0+), and `ImportExcel` (7.8+). Excel is **not** needed.
- Internet access to `login.microsoftonline.com` and `graph.microsoft.com`

## Install

```powershell
# 1. get the folder onto the machine (zip from Build-Package, or clone), then:
Unblock-File -Path .\*.ps1 -ErrorAction SilentlyContinue
Get-ChildItem -Recurse -Include *.ps1,*.psm1,*.xaml,*.cs | Unblock-File

# 2. install modules (per user, no admin needed)
pwsh -File .\Install-Prerequisites.ps1

# 3. run
pwsh -STA -File .\Start-MspTapGenerator.ps1
```

If scripts are blocked by policy, either sign them (see Build) or run `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser`.

## Build

```powershell
pwsh -File .\Build-Package.ps1                       # lint + tests + zip into dist\
pwsh -File .\Build-Package.ps1 -CertThumbprint <thumbprint>   # also code-sign every script
pwsh -File .\Build-Package.ps1 -SkipTests
```

The output is `dist\MspTapGenerator-<version>.zip` plus a `.sha256` file. Unzip, run `Install-Prerequisites.ps1`, then `Launch.cmd`. There is no compile step. It is scripts, XAML and one small C# file that PowerShell compiles at start-up.

Run tests on their own: `Invoke-Pester .\tests`

## Using it

1. **Sign in.** Choose a saved customer or type the tenant ID or domain. Choose Interactive or Device code. Saved customers keep the name and tenant ID only.
2. **Import Users.** Add users from CSV, XLSX or Entra. They land in the work queue (tick/untick, remove). Duplicates are dropped.
3. **Generate TAPs.** Set lifetime and options, click **Validate**, read the results (failures show in their own grid), then **Generate TAPs**. You get a confirmation naming the customer and tenant ID.
4. **Results.** TAPs are masked. Use Show TAPs, Copy row/selected, or Export XLSX.
5. **Logs.** Filter by level or category. Audit entries record who signed in to which tenant, the ticket / change reference, and what was run (never the TAP).

CSV formats accepted (header names are not case sensitive, `UPN`, `Email` and `Name` also work):

```
UserPrincipalName
user1@contoso.com
```
```
UserPrincipalName,DisplayName
user1@contoso.com,Joe Bloggs
```

## Roles the signed-in admin needs

The Graph permissions are only half of it. The admin account also needs an Entra role in the customer tenant:

- **Authentication Administrator**: can create TAPs for non-admin users.
- **Privileged Authentication Administrator**: needed to create TAPs for users who hold admin roles.

For partners using GDAP, the relationship must include one of those roles. PIM-eligible roles must be activated first.

## Multi-tenant notes (important for MSPs)

- The first sign-in to a customer tenant needs **admin consent** for the delegated permissions. The default app (Microsoft Graph Command Line Tools) often cannot be consented by a GDAP partner account.
- The clean fix is your own multi-tenant app registration: public client, redirect `http://localhost`, "Allow public client flows = Yes" (for device code), delegated permissions as listed in `docs/GRAPH-PERMISSIONS.md`. Each customer consents once. Paste its client ID under **Advanced** on the sign-in screen, or set `ClientId` in `%LOCALAPPDATA%\MspTapGenerator\settings.json`.
- If you type a tenant GUID and Entra signs you in to a different tenant, the tool signs you straight back out.
- Switching tenant clears the queue and all TAPs from memory.

## Known limits

- TAP length is policy-level (see above).
- Users are validated one by one with `Get-MgUser`. For several thousand users validation takes a while. It is steady and throttle-safe rather than fast.
- TAP creation is deliberately sequential. Graph throttles writes per tenant, so parallel calls would only trigger 429s.
- A user can only have one usable TAP. Creating a new one replaces the old one (Microsoft's behaviour). Validation flags these users as a warning and the confirmation prompt counts them.
- A TAP can only be created if the tenant policy allows the lifetime you pick. Default tenant policy is 1 hour minimum, 8 hours maximum, so `30 minutes`, `24 hours` and `7 days` will be rejected until the policy range is widened. The pre-flight check tells you before anything is created.
- If the Graph sign-in is not visible to the worker thread on your machine, the app switches itself to "compatibility mode" and runs Graph calls on the UI thread (window may pause briefly). You will see a note on the sign-in screen.
- "Clear from memory" is best effort. See `docs/SECURITY.md`.

## Open questions worth answering before roll-out

- Which customers are on GDAP and which have their own admin accounts? That decides how consent works.
- Do you want your own app registration (recommended) or the Microsoft one?
- Is the TAP policy enabled and targeted at "All users" for each customer, or only a group?
- Where should exported workbooks live, and who is allowed to open them? Suggest a password-protected workbook on an encrypted drive.

## Pilot checklist

- [ ] `Install-Prerequisites.ps1` finishes clean
- [ ] App opens, theme toggle works in both modes
- [ ] Interactive sign-in to a test tenant shows the right customer name and tenant ID
- [ ] Device-code sign-in works (code shown in window)
- [ ] Import each of CSV, XLSX, Entra lookup
- [ ] Validate flags a disabled user, a missing user and a guest
- [ ] Generate for 2-3 users, check the TAP works at an Autopilot sign-in
- [ ] Export masked and unmasked, open the files
- [ ] Open the log file and confirm no TAP value appears anywhere
- [ ] Sign out, sign in to a second tenant, confirm the queue was cleared

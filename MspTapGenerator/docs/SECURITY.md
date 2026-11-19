# Security design

## What the tool stores on disk

| Item | Where | Notes |
|---|---|---|
| Settings (theme, client ID, timeouts) | `%LOCALAPPDATA%\MspTapGenerator\settings.json` | No secrets |
| Tenant profiles | `%LOCALAPPDATA%\MspTapGenerator\profiles.json` | Customer name + tenant ID only |
| Logs | `%LOCALAPPDATA%\MspTapGenerator\Logs\mspTap_YYYYMMDD.jsonl` | Deleted after 90 days (setting) |
| Exports | wherever the admin saves them | The only place a TAP can be written, and only if the admin chooses an unmasked export |

No passwords, access tokens or refresh tokens are saved. Interactive sign-in uses `-ContextScope Process`, so the Graph SDK does not persist a token cache. The device-code refresh token lives in process memory only (a `SecureString`), and is wiped on sign-out.

## TAP handling

1. The SDK returns the TAP as a plain string. It is converted to a `SecureString` immediately and the property on the response object is nulled.
2. Rows in the results grid hold the `SecureString`. Plain text exists only while: the grid is revealed, a value is being copied, or a file is being exported.
3. The grid is masked by default and **auto-hides** after 30 seconds.
4. **Log scrubbing.** TAP values are never passed to the logger. As a second layer, each TAP is also registered as a secret, and `Protect-LogText` replaces any occurrence in any log line (also bearer tokens, JWTs, and `temporaryAccessPass` JSON members in echoed Graph errors). Tested in `tests/MspTap.Tests.ps1`.
5. **Clipboard.** Copies are flagged `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory=0`, `CanUploadToCloudClipboard=0` (no Win+V history, no cloud sync) and cleared after 60 seconds if the clipboard still holds the same value (compared by hash).
6. **Export.** Masked by default (`********`). If unmasked and not password-protected, the admin gets a warning. Optional AES-encrypted workbook. After an unmasked export the TAPs are cleared from memory (default on).
7. Sign-out, tenant switch and closing the window all clear TAP values and warn first if any are still held.

**Honest limit:** .NET strings are immutable and the garbage collector may leave copies in memory until collected. A `SecureString` reduces exposure; it does not make memory forensics impossible. The Graph SDK's own response object also briefly holds the plain value. Treat the workstation as in scope for the same controls you use for a password vault: disk encryption, EDR, locked screen.

## Authentication

- Interactive (MSAL via `Connect-MgGraph`) or OAuth2 device code (shown in the app, then `Connect-MgGraph -AccessToken`).
- Tenant is always explicit. If a GUID was requested and a different tenant comes back, the session is dropped.
- A confirmation naming the customer and tenant ID appears before every generation run. This is the main guard against creating passes in the wrong customer.
- Use your own app registration where you can. Conditional Access applies as normal (use a compliant device and phishing-resistant MFA for the admin account).

## Other hardening

- Spreadsheet formula injection: display names starting with `= + - @` are prefixed with `'` on export.
- OData filter values are escaped (`'` doubled); search text has quotes stripped.
- CSV size limit 20 MB. Imports validate UPN shape and drop duplicates.
- The "Open page" button only opens `https://microsoft.com`, `microsoft.com` or `login.microsoftonline.com` URLs.
- Workbook passwords are read from a `PasswordBox` and not stored or logged.
- Package signing supported through `Build-Package.ps1 -CertThumbprint`.

## Audit trail

`Audit` log entries record: sign-in (tenant, admin, scopes), each generation batch (counts, lifetime, one-time, delayed start), policy length changes, exports (file name, masked or not, encrypted or not). Each line carries session ID, customer name, tenant ID and admin UPN. User UPNs appear in per-user result lines. Every line also carries the **ticket / change reference** typed on the Generate tab (shown in the confirmation prompt, written to the log, and stored in the exported workbook's Subject property). Set `"RequireTicket": true` in `settings.json` to make it mandatory.

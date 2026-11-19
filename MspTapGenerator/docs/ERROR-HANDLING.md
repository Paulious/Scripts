# Error handling strategy

**Principle:** one bad user never stops a batch, one bad batch never loses results, and nothing sensitive ends up in an error message.

| Layer | What happens |
|---|---|
| Pre-flight (before any write) | Missing scopes, TAP method disabled, lifetime outside policy range, activation time in the past: **stop with a clear message**. Unreadable policy or unverifiable admin role: **warn and continue**. |
| Per-user validation | Not found, disabled, guest = `Failed` (shown in the separate failures grid). Existing TAP = `Warning`. Nothing is created for `Failed` users. |
| Throttling / transient | 429/503/504 retried with exponential back-off and jitter. Progress keeps running. Cancel works during a wait. |
| Per-user creation failure | Recorded on the row with a friendly reason plus the Graph error code, then the batch moves on. |
| Repeated 401/403 | After 3 in a row the batch stops (almost always a missing role or consent). Results so far are kept. |
| Token expiry | Interactive: MSAL refreshes. Device code: the app refreshes with the in-memory refresh token 5 minutes before expiry. |
| Cancel | Stops after the current user. Partial results stay in the grid. |
| Policy length change | Restored in a `finally` block even if the batch fails or is cancelled. If restore fails, a warning tells you the old value to set manually. |
| Worker problems | If background workers cannot be used (pool will not open, or Graph sign-in not shared with the worker) the app falls back to running Graph calls on the UI thread. |
| UI exceptions | Caught by the dispatcher handler, logged, shown in the status bar. The app stays open. |
| Import / export | Bad rows are skipped and counted with reasons. File problems show a message in the tab. Export failures never clear TAPs. |
| Logging | Never throws. Every message passes through `Protect-LogText`. |

## Friendly messages

| Graph result | Shown as |
|---|---|
| 403 | Signed-in admin needs Authentication Administrator (or Privileged Authentication Administrator for admin users) |
| 404 | User not found |
| 400, policy wording | TAP is not enabled for this user in the Authentication methods policy |
| 429 exhausted | Throttled by Graph and retries were used up. Retry failures later |
| 401 | Session expired. Sign in again |

The raw Graph code and message are appended in square brackets (scrubbed) so you can search them or send them to Microsoft.

## Retry and recovery

- **Retry failures** re-runs only users whose result row is `Failed`, with the current options, after a fresh confirmation.
- **Export failures** writes `TAP_Failures_<timestamp>.xlsx` (validation and generation failures, with stage and reason).

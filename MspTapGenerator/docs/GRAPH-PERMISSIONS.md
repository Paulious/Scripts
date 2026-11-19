# Graph permission model

All permissions are **delegated** (the tool acts as the signed-in admin). Nothing is app-only.

| Permission | Required | Why |
|---|---|---|
| `User.Read.All` | Yes | `Get-MgUser`: search, filters, validation (exists / enabled / member) |
| `UserAuthenticationMethod.ReadWrite.All` | Yes | Create TAPs; read existing TAPs. Needs admin consent. |
| `Directory.Read.All` | Yes | Organization name, group membership, admin role check |
| `AuditLog.Read.All` | Yes | Requested as specified. Reserved for sign-in/audit checks; not needed for creating TAPs |
| `Policy.Read.All` | Optional (on by default) | Read the TAP policy: enabled, lifetime range, one-time-only, length, targets |
| `Policy.ReadWrite.AuthenticationMethod` | Optional (off by default) | Only when you tick "Apply this length to the tenant TAP policy" |

`UserAuthMethod-TAP.ReadWrite.All` is a narrower permission that Microsoft lists for creating TAPs. It would work for creation only. The tool keeps `UserAuthenticationMethod.ReadWrite.All` as you specified.

Without `Policy.Read.All` everything still works. The policy shows as "Unknown" and the lifetime/enabled checks are skipped (Graph then rejects bad requests itself).

## Entra roles (the signed-in admin)

| Role | Can create TAPs for |
|---|---|
| Authentication Administrator | Non-admin members |
| Privileged Authentication Administrator | Any user including admins |
| Global Administrator | Any user |

Guests cannot use TAP. The validation step marks them as failed.

## Cmdlets and endpoints used

| Action | Cmdlet / call |
|---|---|
| Sign in | `Connect-MgGraph -Scopes ... -ContextScope Process` or `-AccessToken` after device code |
| Tenant name | `Get-MgOrganization` |
| Find users | `Get-MgUser -Filter/-Search -ConsistencyLevel eventual` |
| Group members | `Get-MgGroupTransitiveMemberAsUser`, `Get-MgGroup -Search` |
| Validate user | `Get-MgUser -UserId`, `Get-MgUserAuthenticationTemporaryAccessPassMethod` |
| **Create TAP** | `New-MgUserAuthenticationTemporaryAccessPassMethod` (`lifetimeInMinutes`, `isUsableOnce`, `startDateTime`) |
| Policy read/write | `Invoke-MgGraphRequest` on `/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/TemporaryAccessPass` |
| Admin roles | `Invoke-MgGraphRequest` on `/me/transitiveMemberOf/microsoft.graph.directoryRole` |

## Throttling

429, 503 and 504 are retried up to 6 times with exponential back-off (2, 4, 8... up to 60 seconds) plus up to 1 second of jitter. `Retry-After` is honoured when Graph sends it. Creation is sequential with a 150 ms pause. Other errors are not retried. 3 authorization failures in a row stop the batch.

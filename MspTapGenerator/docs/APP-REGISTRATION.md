# Setting up your own app registration

Do this once, in **your MSP tenant**. Then each customer consents once. About 15 minutes.

## Why bother
Sign-ins show your app name instead of "Microsoft Graph Command Line Tools". You choose the permissions. Customers can review and revoke one clearly named app. Consent is easier to get than for the Microsoft app. See the comparison in the README.

## 1. Create the registration
Entra admin centre, **App registrations**, **New registration**.

| Setting | Value |
|---|---|
| Name | `MSP TAP Generator` (customers will see this) |
| Supported account types | **Accounts in any organizational directory (Multitenant)** |
| Redirect URI | Platform **Mobile and desktop applications**, value `http://localhost` |

Copy the **Application (client) ID**. This is the only value the tool needs. There is no secret, and you should not create one.

## 2. Allow device code sign-in
**Authentication**, then **Advanced settings**, then **Allow public client flows = Yes**. Save.

## 3. Add the permissions
**API permissions**, **Add a permission**, **Microsoft Graph**, **Delegated permissions**. Add:

- `User.Read.All`
- `UserAuthenticationMethod.ReadWrite.All`
- `Directory.Read.All`
- `AuditLog.Read.All`
- `Policy.Read.All` (optional, lets the tool read the TAP policy)
- `Policy.ReadWrite.AuthenticationMethod` (optional, only if you will change TAP length)

Do not add application permissions. Do not click grant admin consent in your own tenant unless you also want to use the tool there.

Tip: set the **Publisher domain** and a logo. A verified publisher makes the customer's consent screen less scary.

## 4. Get each customer to consent
A customer **Global Administrator** (or Privileged Role Administrator) opens this link while signed in to their tenant. Replace the two values:

```
https://login.microsoftonline.com/<customer-tenant-id>/adminconsent?client_id=<your-client-id>
```

They review the list and accept. Afterwards the app appears under their **Enterprise applications**.

Send the link in your onboarding email. Keep a record of who consented and when (ticket number).

If you use GDAP: only try to consent yourself if the relationship includes a role that is allowed to grant consent. If it does not, ask the customer. Consent for delegated permissions does not give you access by itself. Your admin still needs the Entra role (Authentication Administrator or Privileged Authentication Administrator).

## 5. Point the tool at it
Either:

- Sign-in screen, **Advanced**, paste the client ID, or
- Edit `%LOCALAPPDATA%\MspTapGenerator\settings.json` and set `"ClientId": "<your-client-id>"`.

The tool checks that it is a GUID and nothing else. It is not a secret.

## 6. Test
Sign in to one customer. The Dashboard should show every required scope with a tick. If one is missing, consent was not given for it. Re-send the link, or add the missing permission to the registration first.

## Common problems

| Message | Likely cause |
|---|---|
| AADSTS65001 (consent required) | Customer has not consented yet. Send the link from step 4. |
| AADSTS50011 (reply URL mismatch) | Redirect URI missing, or added under "Web" instead of "Mobile and desktop". |
| AADSTS7000218 / device code fails | "Allow public client flows" is still No. |
| AADSTS700016 (app not found in tenant) | App is single-tenant. Change to multitenant. |
| AADSTS53003 / blocked | Customer Conditional Access blocks the sign-in. Use a compliant device, or ask them to include your admin accounts. |
| Dashboard shows a scope missing | Permission not added to the registration, or customer consented before you added it. Consent again. |

## Housekeeping
- Add a second owner to the registration so it is not tied to one person.
- Review the permission list every few months. Remove the optional policy scopes if you do not use them.
- Never put a client secret or certificate on this app. The tool does not need one.

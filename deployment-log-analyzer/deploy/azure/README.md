# Hosting on Azure

This puts the analyzer on Azure Container Apps, behind Microsoft Entra sign-in, using the Anthropic key you already have (or Azure OpenAI, or no AI at all).

## What gets created

| Resource | What it is for |
|---|---|
| Container Registry (Basic) | Holds the three images. They are built inside Azure, not on your PC. |
| Container Apps environment | Where the apps run. |
| `dla-proxy` app | The only thing reachable from the internet. Sends `/` to the website and `/api` to the analysis service, so there is one address and one sign-in. |
| `dla-web` app | The website. Internal only. |
| `dla-api` app | The analysis service. Internal only. 2 CPUs and 4 GB of memory, because uploaded files are handled in memory. |
| Managed identity | Lets the apps pull images from the registry without a password. Also used to call Azure OpenAI if you choose that. |
| Log Analytics workspace | Platform logs, kept for 30 days. |

The apps store nothing. There is no database and no storage account.

## Before you start

You need:
- The [Azure CLI](https://aka.ms/installazurecli), signed in with `az login`, and PowerShell 5.1 or newer.
- Permission to create resources in a subscription (Contributor on the subscription or on an empty resource group).
- For automatic sign-in setup, permission to create app registrations in Entra ID. Many company tenants limit this. If yours does, ask an admin to follow "If you cannot create the app registration" below.
- The resource providers registered once per subscription:

```powershell
az provider register --namespace Microsoft.App
az provider register --namespace Microsoft.OperationalInsights
az provider register --namespace Microsoft.ContainerRegistry
```

## Deploy

From the `deployment-log-analyzer\deploy\azure` folder:

```powershell
.\deploy.ps1 -ResourceGroup rg-log-analyzer
```

It asks for your Anthropic API key (press Enter to skip AI), then does everything in order. It takes roughly 10 to 15 minutes, mostly building the images. At the end it prints the address.

What the script does:
1. Creates the resource group, registry, identity, logging and environment.
2. Creates an Entra app registration for sign-in, limits it to people you assign, and assigns you.
3. Builds the three images in the registry.
4. Deploys the apps and turns sign-in on.

Useful options:

| Option | Meaning |
|---|---|
| `-Location uksouth` | Azure region. |
| `-AnthropicApiKey ...` | Skip the prompt. |
| `-AzureOpenAiEndpoint ... -AzureOpenAiDeployment ...` | Use Azure OpenAI instead. No key is stored. See below. |
| `-AllowedIp 203.0.113.4/32` | Only let this address in. Can be used with or instead of sign-in. |
| `-SkipAuthSetup` | Do not create an app registration. Requires `-AllowedIp`. |
| `-AuthClientId` and `-AuthClientSecret` | Use an app registration an admin made for you. |

The script refuses to deploy a site with no sign-in and no IP limit. Without one of them anyone could upload files and spend your API credit.

## Letting other people in

If the script created the app registration, only people you assign can sign in. Add them in the portal under **Microsoft Entra ID, Enterprise applications, Deployment Log Analyzer (...), Users and groups**. Assigning a security group is easiest. Someone who is not assigned sees error AADSTS50105.

## If you cannot create the app registration

Ask an admin to create one with these settings, then give you the client ID and a client secret:
- Supported account types: this organisation only.
- Redirect URI (Web): `https://dla-proxy.<environment domain>/.auth/login/aad/callback`. The deploy script prints the address in its first step ("Site will be at"). Stop there if you need it before the app registration exists.
- ID tokens enabled.
- On the Enterprise application, turn on "Assignment required" and assign the right group.

Then run the script with `-AuthClientId` and `-AuthClientSecret`.

## The AI key

Your Anthropic key is stored as a Container Apps secret on `dla-api`. Keys created in the Console can expire (yours was set to 30 days). To replace it:

```powershell
az containerapp secret set --name dla-api --resource-group rg-log-analyzer --secrets anthropic-api-key=NEW_KEY
az containerapp revision restart --name dla-api --resource-group rg-log-analyzer --revision (az containerapp revision list --name dla-api --resource-group rg-log-analyzer --query "[0].name" -o tsv)
```

Or just run `deploy.ps1` again with the new key.

### Azure OpenAI instead

Pass `-AzureOpenAiEndpoint https://<name>.openai.azure.com` and `-AzureOpenAiDeployment <deployment name>`. There is no key. The API signs in with the managed identity, so after deploying, give that identity access to the Azure OpenAI resource:

```powershell
$id = az identity show --name dla-id --resource-group rg-log-analyzer --query principalId -o tsv
az role assignment create --assignee-object-id $id --assignee-principal-type ServicePrincipal `
  --role "Cognitive Services OpenAI User" --scope <resource id of the Azure OpenAI resource>
```

Because the model runs in your own tenant, this is the better choice if log data must not leave it.

## Day to day

- **Update the code:** pull the latest, run `deploy.ps1` again with the same options. Existing resources and the sign-in app registration are reused, and the API key already stored in Azure is kept unless you pass a new one. It rebuilds the images each time, so allow a few minutes.
- **Logs:** `az containerapp logs show --name dla-api --resource-group rg-log-analyzer --follow`. The service never writes file names or contents to its logs.
- **First request after a quiet spell is slower** because the API and website can scale to zero. Set `minReplicas` to 1 in `apps.bicep` if that bothers you.
- **Remove everything:** `az group delete --name rg-log-analyzer`.

## What has and has not been tested

Tested:
- The Bicep templates compile with no warnings.
- The proxy configuration was run with nginx in front of the real website and API, including the whole upload, progress and AI flow in a browser through one address, rejection of oversized uploads, and progress arriving live instead of in one lump.

Not tested, because it needs a real Azure subscription:
- The deployment itself. Expect the odd first-run issue, and tell me the exact message if you hit one.
- `deploy.ps1` has not been run. It was written for Windows PowerShell 5.1 and checked by reading.
- Entra sign-in in front of a streaming response. I expect it to pass events through, but check that the progress bar moves while a large ZIP is analysed.
- Azure's own request time limit. A very slow AI analysis could hit it. The app sends a keep-alive every 15 seconds to reduce that risk.

Troubleshooting:
- **Image pull errors straight after deploying:** the registry permission can take a minute or two to apply. Run `deploy.ps1` again.
- **Redirect URI mismatch at sign-in:** the redirect URI on the app registration must match the site address exactly, including `/.auth/login/aad/callback`.
- **Sign-in works but you get a 403:** you are not assigned to the app, or your IP is not on the allow-list.

## Using your own address

To use something like `logs.example.com` instead of the long Azure address:

1. Get the two values: the current site address (`az containerapp show -g <group> -n dla-proxy --query properties.configuration.ingress.fqdn -o tsv`) and the verification code (`... --query properties.customDomainVerificationId -o tsv`).
2. In your DNS add a CNAME `logs` pointing at the site address, and a TXT record `asuid.logs` holding the verification code. If you use Cloudflare, set both to **DNS only** (grey cloud). Azure cannot issue its certificate through the proxy, and Cloudflare's proxy also cuts long requests and large uploads.
3. Run the deploy script with `-CustomDomain logs.example.com`. It attaches the name, gets the certificate and adds the sign-in redirect address. Keep the option on every later run, because a redeploy resets host names.

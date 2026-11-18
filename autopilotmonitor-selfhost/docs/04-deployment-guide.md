# 04. Deployment guide (tenant: clefsoft.co.uk)

Nothing here has been run against your tenant. Treat the first run of every script as a rehearsal: use `-WhatIf` (PowerShell) and `what-if` (Bicep).

## Part 1. Naming standard and tenant plan

Region: **UK South** (`uksouth`, code `uks`). Exceptions: Static Web App management plane in **West Europe** (UK South is not offered).

| Resource | Name | Rule |
|---|---|---|
| Resource group | `rg-autopilotmonitor-prod-uks` | `rg-<workload>-<env>-<region>` |
| Function app | `func-autopilotmonitor-prod` | globally unique; add `-xx` suffix if taken |
| Function plan | `asp-autopilotmonitor-prod-uks` | Flex Consumption FC1 |
| Storage (data) | `stautopilotmonitorprod` | 22 chars; global; 2-char `uniqueSuffix` fits |
| Storage (host) | `stautopilotmonitorfnprod` | 24 chars; keep suffix empty or use a shorter workload |
| Key Vault | `kv-autopilotmonitor-prod` | exactly 24 chars, **no room for a suffix**; if taken or soft-deleted, change `workload` |
| SignalR | `sigr-autopilotmonitor-prod` | |
| Static Web App | `swa-autopilotmonitor-prod` | |
| Log Analytics | `log-autopilotmonitor-prod-uks` | |
| App Insights | `appi-autopilotmonitor-prod-uks` | |
| ACR | `acrautopilotmonitorprod` | alphanumeric only |
| Container Apps env / app | `cae-autopilotmonitor-prod-uks` / `ca-autopilotmonitor-mcp-prod` | |
| MCP identity | `id-autopilotmonitor-mcp-prod-uks` | user-assigned |
| Entra app | `Autopilot Monitor (clefsoft)` | |
| Groups | `AutopilotMonitor-Devices`, `Autopilot-Pilot`, `AutopilotMonitor-Admins` | |
| Tags | `workload`, `environment`, `managedBy`, `purpose` | applied by Bicep |

**Default hostnames** (no custom domain in the lab): `https://<function>.azurewebsites.net` (newer apps may get a hashed host; always use the Bicep output), `https://<swa>.azurestaticapps.net`, `https://<app>.<env>.uksouth.azurecontainerapps.io`.
**Custom domains (recommended once stable):** `autopilot.clefsoft.co.uk` (portal), `api-autopilot.clefsoft.co.uk` (API), `mcp-autopilot.clefsoft.co.uk` (MCP). Changing a host later means re-running the patcher and **rebuilding and re-signing the agent**, so decide early if you want vanity URLs. Also note: a custom domain does **not** make existing agents move; the baked URL is what they use.

## Part 2. Walkthrough (Option B: IaC + scripts, recommended)

Run from a PowerShell 7 prompt on your workstation. `<…>` are values you fill in.

### Step 0. Sign in and set variables
```powershell
az login --tenant clefsoft.co.uk
az account set --subscription "<subscription name or id>"
az functionapp list-flexconsumption-locations --query "[?name=='uksouth']" -o table   # must return a row (G14)

$rg       = 'rg-autopilotmonitor-prod-uks'
$loc      = 'uksouth'
$me       = az ad signed-in-user show --query id -o tsv          # your object id
$tenantId = az account show --query tenantId -o tsv
Write-Host "tenant: $tenantId  me: $me"
```

### Step 1. Resource group
```powershell
az group create --name $rg --location $loc --tags workload=autopilotmonitor environment=prod
```

### Step 2. Infrastructure, pass 1 (core platform, no MCP, no client id yet)
Edit `bicep/main.bicepparam`: set `deployerObjectId` to `$me`, `budgetAlertEmail`, and `rulesBaseUrl` (your fork). Then:
```powershell
cd <repo>/autopilotmonitor-selfhost/bicep
az deployment group what-if --resource-group $rg --template-file main.bicep --parameters main.bicepparam
az deployment group create  --resource-group $rg --template-file main.bicep --parameters main.bicepparam --name pass1
az deployment group show -g $rg -n pass1 --query properties.outputs -o json | Tee-Object -Variable out1
$o = ($out1 | ConvertFrom-Json)
$api = $o.apiBaseUrl.value; $portal = $o.portalUrl.value; $kv = $o.keyVaultName.value; $stg = $o.dataStorageName.value
```
**Expect:** no errors, outputs for `apiBaseUrl`, `portalUrl`, `keyVaultName`, `agentContainerUrl`. **If the storage name is taken:** set `uniqueSuffix = 'c1'` and re-run (note: the host storage name is 24 chars already and is truncated, check the output).
**Expect on the Function app now:** HTTP 5xx or "Key Vault reference not found", because the secrets do not exist yet. That is normal at this point.

### Step 3. Entra app registration and the client secret
```powershell
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Groups, Microsoft.Graph.Identity.SignIns -Scope CurrentUser
cd ../scripts
./02-New-EntraAppRegistration.ps1 -TenantId $tenantId -PortalUrl $portal -KeyVaultName $kv `
    -OptionalFeatures IntuneDeviceBinding -PreAuthorizeAzureCli -WhatIf     # rehearse
./02-New-EntraAppRegistration.ps1 -TenantId $tenantId -PortalUrl $portal -KeyVaultName $kv `
    -OptionalFeatures IntuneDeviceBinding -PreAuthorizeAzureCli
```
Write down the **AppId** it prints. Verify in Entra admin center: *App registrations > Autopilot Monitor (clefsoft)*: Supported account types = *multiple organizations*; *Expose an API* shows `api://<appId>` + `access_as_user`; *API permissions* shows Graph `DeviceManagementServiceConfig.Read.All` with a green tick.

Then, in **Entra admin center > Enterprise applications > Autopilot Monitor (clefsoft) > Properties**, set **Assignment required = Yes**, and assign `AutopilotMonitor-Admins` after step 12.

### Step 4. Other secrets
```powershell
./04-Initialize-Secrets.ps1 -ResourceGroup $rg -KeyVaultName $kv -SignalRName $o.signalRName.value -FunctionAppName $o.functionAppName.value
```

### Step 5. Infrastructure, pass 2 (client id + MCP with placeholder image)
In `main.bicepparam`: `entraClientId = '<appId>'`, `deployMcp = true`.
```powershell
cd ../bicep
az deployment group create -g $rg --template-file main.bicep --parameters main.bicepparam --name pass2
$o = (az deployment group show -g $rg -n pass2 --query properties.outputs -o json | ConvertFrom-Json)
$mcp = $o.mcpPublicUrl.value; $acr = $o.acrName.value
$mcp
```
Add the MCP callback to Entra now that the URL exists:
```powershell
cd ../scripts
./02-New-EntraAppRegistration.ps1 -TenantId $tenantId -PortalUrl $portal -McpUrl $mcp -KeyVaultName $kv   # existing app: updates redirect URIs only
```

### Step 6. Fork preparation (the rebuild part)
```powershell
# Fork okieselbach/AutopilotMonitor on GitHub first. Then:
git clone https://github.com/<you>/AutopilotMonitor.git; cd AutopilotMonitor
# Do NOT run `git submodule update`: the three submodules are private. .gitmodules sets update=none.
mkdir deploy/selfhost; Copy-Item -Recurse <this pack>/* deploy/selfhost/     # never use the infra/ folder
Copy-Item deploy/selfhost/scripts/selfhost.config.example.json deploy/selfhost/scripts/selfhost.config.json
```
Edit `selfhost.config.json`: `apiBaseUrl=$api`, `portalUrl=$portal`, `mcpUrl=$mcp`, `dataStorageAccount=$stg`, `publisherOrg` = the **Organisation (O=) in your signing certificate's subject** (step 8 decides this, so settle the certificate first or re-run the patcher later; it is idempotent).
```powershell
cd deploy/selfhost/scripts; npm install
node 01-set-selfhost-endpoints.mjs --repo ../../.. --config selfhost.config.json            # dry run
node 01-set-selfhost-endpoints.mjs --repo ../../.. --config selfhost.config.json --apply
```
**Tested result on the real repo:** 38 replacements, 11 files. What remains are comments, placeholders and legal pages.

Then, by hand:
1. **Legal pages** (G11): edit `app/privacy/page.tsx`, `app/terms/page.tsx`, `app/about/page.tsx`, `components/SiteFooter.tsx`, `app/layout.tsx` (organisation name). Keep the AGPL/MIT notices and attribution.
2. **Guard tests** assert the OLD strings (`HardcodedUrlGuardTests.cs`, `hardcodedUrls.guard.test.ts`, `hardcoded-urls.guard.test.ts`, `CodeSigningParityTests`). Run them and update the expected values deliberately:
   `dotnet test src/Backend/AutopilotMonitor.Functions.Tests` and `npm test` in the web and MCP folders. I could not run these here (no .NET SDK).
3. Commit to a branch, open a PR in **your** fork, merge to `main`.

### Step 7. GitHub Actions identity (OIDC, no stored secrets)
```powershell
$repo = '<you>/AutopilotMonitor'
$app  = az ad app create --display-name 'gh-autopilotmonitor-deploy' --query "{appId:appId,id:id}" -o json | ConvertFrom-Json
az ad sp create --id $app.appId | Out-Null
az ad app federated-credential create --id $app.id --parameters (@{
  name='gh-production'; issuer='https://token.actions.githubusercontent.com'
  subject="repo:${repo}:environment:production"; audiences=@('api://AzureADTokenExchange') } | ConvertTo-Json)
$sub = az account show --query id -o tsv
az role assignment create --assignee $app.appId --role Contributor --scope "/subscriptions/$sub/resourceGroups/$rg"   # infra workflow
```
Then in the GitHub repo: **Settings > Environments > production** (add yourself as required reviewer, restrict to `main`); add secrets `AZURE_CLIENT_ID`=`$($app.appId)`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`; variables `AZURE_RESOURCE_GROUP`, `FUNCTION_APP`, `API_BASE_URL`, `PORTAL_URL`, `STATS_URL` (=`<agentContainerUrl minus /agent>/stats`), `NEXT_PUBLIC_ENTRA_CLIENT_ID`. Add secret `AZURE_SWA_DEPLOY_TOKEN`:
```powershell
az staticwebapp secrets list --name $o.staticWebAppName.value --query properties.apiKey -o tsv
```
**Tighten later:** Contributor on the RG is broad for a pipeline that only deploys code. Once infra is stable, replace it with *Website Contributor* on the Function app, plus data roles on the `agent` container for the agent pipeline.
Copy `ci/*.yml` to `.github/workflows/`.

### Step 8. Code-signing (gap G3, the long pole)
You need a certificate whose chain a **fresh Windows device already trusts**, because the loader runs during OOBE before you can install anything. Choose one:

| Route | Works on real devices? | Effort | Notes |
|---|---|---|---|
| **Purchased OV code-signing certificate**, imported to a *dedicated* Key Vault | Yes | Identity validation can take days. 1 to 3 days elapsed. | Matches upstream's pipeline (AzureSignTool + Key Vault). Many CAs now require HSM-backed keys; check Key Vault Premium or Managed HSM needs with the CA. |
| **Azure Artifact Signing** (formerly Trusted Signing) | Yes | You must change the signing steps in `build-agent.yml`, `build-msi.yml`, `Publish-BootstrapScripts.ps1` | Verify it is offered to UK organisations and what it costs today. **Not verified by me.** |
| **Self-signed, lab only** | **Only on test VMs where you installed the certificate into LocalMachine\Root and TrustedPublisher before Autopilot** | Hours | Cheapest, zero lead time. Not production-like. Do not use on real hardware. |

Repository **variables** the upstream agent workflow reads: `CODE_SIGN_CLIENT_ID`, `CODE_SIGN_CERTIFICATE_NAME`, `CODE_SIGN_KEY_VAULT_URL`, `CODE_SIGN_EXPECTED_SUBJECT` (must match `*O=<publisherOrg>*`). The workflow login identity needs permission to **sign** with the key (`Key Vault Crypto User`) and **read** the certificate (`Key Vault Certificate User` or secrets get).

### Step 9. Publish the agent, MSI and scripts
Run the upstream workflows in your fork (they read hosts from the patched `Get-Endpoints.ps1`):
1. **Build Agent**: input `publish_as_stable = true`, `upload_blob = true`. Writes `AutopilotMonitor-Agent.zip`, `version.json` to the `agent` container and sets `LatestAgentV2Version/Sha256/ExeSha256` on the AdminConfiguration row.
2. **Publish scripts**: signs and uploads `Install-AutopilotMonitor.ps1`, `Start-AutopilotMonitor.ps1`, `Test-ShouldBootstrapAgent.ps1`; sets `LatestBootstrapV2ScriptVersion`.
3. **Build & Publish Bootstrap MSI** (for Device Preparation).

Two upstream details you will hit: (a) the workflows also try to mirror to a *legacy* storage account if `AZURE_BLOB_AGENT_LEGACY_SAS_TOKEN` is set. Leave that secret **unset**; the mirror is fail-soft. (b) The pipeline's Azure identity needs **Storage Blob Data Contributor** on the data account **and Storage Table Data Contributor** (it merges the AdminConfiguration row). Grant both to the OIDC identity from step 7.

Verify: `07-Test-Deployment.ps1` (agent blob checks should now pass), and download the script, then `Get-AuthenticodeSignature .\Start-AutopilotMonitor.ps1` must say **Valid** and show your organisation.

### Step 10. Deploy backend and web
GitHub > Actions > **Deploy backend** > Run; then **Deploy web** > Run. The backend workflow waits until `/api/health` reports the new commit.

### Step 11. Seed the first admin and activate your tenant
```powershell
cd <repo>/deploy/selfhost/scripts
az login --tenant $tenantId        # the user running this needs Storage Table Data Contributor (granted in pass 1)
node 03-seed-platform.mjs --account $stg --upn "<you>@clefsoft.co.uk" --tenant-id $tenantId --object-id $me
```
**Expect:** three lines and a "Verified read-back" block. (Tested against Azurite; first real run is yours.)

Now load the rules (tables are empty until then):
```powershell
$appId = '<appId>'
$t = az account get-access-token --scope "api://$appId/access_as_user" --query accessToken -o tsv
$h = @{ Authorization = "Bearer $t" }
Invoke-RestMethod -Method Post -Uri "$api/api/rules/reseed-from-github"      -Headers $h
Invoke-RestMethod -Method Post -Uri "$api/api/rules/ime-log-patterns/reseed" -Headers $h
```
If you get `AADSTS65001` the CLI was not pre-authorized: re-run step 3 with `-PreAuthorizeAzureCli`. A `403` means the seed row or identity binding is missing or the token tenant/object id does not match.

### Step 12. First portal sign-in
1. Open `$portal`. Sign in as the seeded admin, accept MFA.
2. Because `AutoApproveNewTenants = true`, your tenant should activate within about a minute (a queue worker does it). You become **Tenant Admin** (first member of the tenant, not a guest).
3. **Settings > Autopilot Validation**: turn on **Autopilot Device Validation** and approve `DeviceManagementServiceConfig.Read.All` (already consented by script; use **Detect existing access** if the redirect fails). Without this the backend rejects every device.
4. **Settings > Hardware Whitelist**: Hyper-V VMs are already covered by `Microsoft Corporation`.
5. **Settings > Diagnostics**: point at **your own storage** if you want packages. Leave off for the first test.
6. Add yourself and colleagues in **Settings > Access Management**, then assign the `AutopilotMonitor-Admins` group to the enterprise app.

### Step 13. Intune
```powershell
./05-New-IntuneGroups.ps1 -TenantId $tenantId -WhatIf ; ./05-New-IntuneGroups.ps1 -TenantId $tenantId
./06-Deploy-IntuneBootstrap.ps1 -TenantId $tenantId -AgentContainerUrl "$($o.agentContainerUrl.value)" -ExpectedPublisher '*O=<your org>*' -GroupName 'Autopilot-Pilot' -WhatIf
```
Details, detection and the Device Prep MSI are in **doc 05**.

### Step 14. MCP server image, final infrastructure re-run
```powershell
cd <repo>
git clone --depth 1 https://github.com/autopilotmonitor/autopilotmonitor-docs mcp-docs      # the Dockerfile COPYs this folder (strict)
az acr build --registry $acr --image autopilotmonitor-mcp:$(git rev-parse --short HEAD) `
   --file src/McpServer/autopilot-monitor-mcp/Dockerfile .
```
In `main.bicepparam`: `mcpImage = '<acr>.azurecr.io/autopilotmonitor-mcp:<tag>'`, `mcpPublicUrl = '<mcp url>'`, then re-run the deployment (`--name pass3`). The first build downloads a ~23 MB embedding model (retries built in; Hugging Face must be reachable from ACR build). `07-Test-Deployment.ps1 -McpUrl $mcp` should pass.

### Step 15. Lock down (milestone M6)
- [ ] `AutoApproveNewTenants` back to **false** (re-run the seed script with `--no-auto-approve`; it merges only that column)
- [ ] `deployerObjectId = ''` and re-deploy (removes your temporary data-plane roles)
- [ ] CA policy for MFA in report-only, then enforced (doc 03)
- [ ] Budget email confirmed; 1 GB/day log cap confirmed
- [ ] Enterprise app: *Assignment required = Yes*
- [ ] Secrets expiry dates in the calendar

## Part 3. Option A: manual deployment (portal-free CLI), for reference

The Bicep is the source of truth. This is the same thing by hand, for people who need to understand each piece. Variables as in step 0.
```powershell
$n='autopilotmonitor'; $e='prod'
az monitor log-analytics workspace create -g $rg -n log-$n-$e-uks --retention-time 30 --quota 1
az monitor app-insights component create -g $rg -a appi-$n-$e-uks -l $loc --workspace $(az monitor log-analytics workspace show -g $rg -n log-$n-$e-uks --query id -o tsv)
az storage account create -g $rg -n st$n$e -l $loc --sku Standard_LRS --allow-shared-key-access false --min-tls-version TLS1_2 --allow-blob-public-access true
az storage account create -g $rg -n st${n}fn$e -l $loc --sku Standard_LRS --allow-shared-key-access false --min-tls-version TLS1_2 --allow-blob-public-access false
az storage container create --account-name st$n$e -n agent    --public-access blob --auth-mode login
az storage container create --account-name st$n$e -n versions --auth-mode login
az storage container create --account-name st$n$e -n stats    --auth-mode login
az storage container create --account-name st${n}fn$e -n app-package --auth-mode login
az keyvault create -g $rg -n kv-$n-$e -l $loc --enable-rbac-authorization true --enable-purge-protection true
az signalr create -g $rg -n sigr-$n-$e -l $loc --sku Free_F1 --service-mode Serverless
az staticwebapp create -g $rg -n swa-$n-$e -l westeurope --sku Free
az functionapp create -g $rg -n func-$n-$e --flexconsumption-location $loc --runtime dotnet-isolated --runtime-version 10.0 `
   --storage-account st${n}fn$e --instance-memory 2048 --maximum-instance-count 10 --assign-identity '[system]' `
   --deployment-storage-auth-type SystemAssignedIdentity
# mTLS (devices) and HTTPS-only. The exact CLI group for Flex client certs may differ by CLI version; if this fails use the portal:
az functionapp update -g $rg -n func-$n-$e --set clientCertEnabled=true clientCertMode=Optional httpsOnly=true
```
Then role assignments (principal = the Function app's system identity) exactly as in doc 02, app settings exactly as in `bicep/modules/functionapp.bicep` (`baseSettings`), and continue at step 3 above.
**Known weak spot of the manual path:** `az functionapp create --flexconsumption-location` and the client-certificate `--set` syntax change between CLI versions; I could not run them here. Prefer Part 2.

## Part 4. azd path (provision only)
`azure.yaml` points `azd provision` at the same Bicep. Use it if your team standardises on azd. Code deployment stays in GitHub Actions. **Untested**; run `azd provision --preview` first. azd cannot replace steps 3, 6, 8, 9 (Entra, patching, signing, agent publishing).

## Part 5. Permissions summary (everything granted anywhere above)

| Where | Identity | Permission | Permanent? |
|---|---|---|---|
| Entra | App registration | Graph application: `DeviceManagementServiceConfig.Read.All` (+ optional `DeviceManagementManagedDevices.Read.All`) | Yes |
| Entra | App registration | Delegated: `access_as_user` (own), `User.Read` | Yes |
| Entra | Azure CLI client app | Pre-authorized on `access_as_user` (only if `-PreAuthorizeAzureCli`) | Optional; remove after setup |
| Azure | Function app MI | Table/Queue/Blob data roles on data account; Blob Owner/Queue/Table on host account; KV Secrets User; Monitoring Reader on App Insights | Yes |
| Azure | MCP user-assigned MI | AcrPull; KV Secrets User | Yes |
| Azure | Deployer (you) | Table Data Contributor, Blob Data Contributor, KV Secrets Officer | **Temporary** |
| Azure | GitHub OIDC identity | Contributor on RG (tighten later) + data roles for the agent pipeline | Yes, reviewed |
| Intune/Graph (scripts) | You, interactive | `Group.ReadWrite.All`, `DeviceManagementConfiguration.ReadWrite.All`, `Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, `DelegatedPermissionGrant.ReadWrite.All` | Delegated, per session |

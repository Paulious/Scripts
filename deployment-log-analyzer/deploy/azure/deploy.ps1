<#
.SYNOPSIS
  Deploys Deployment Log Analyzer to Azure Container Apps.

.DESCRIPTION
  1. Creates the resource group, registry, identity, logging and Container Apps environment.
  2. Creates a Microsoft Entra app registration for sign-in (unless you pass your own).
  3. Builds the three images inside the registry (nothing is built on your PC).
  4. Deploys the web, API and proxy apps.

  Run it again at any time to update the code, rotate the API key or change settings.

.EXAMPLE
  ./deploy.ps1 -ResourceGroup rg-logs-analyzer

.EXAMPLE
  # No sign-in setup, only your office address can reach the site
  ./deploy.ps1 -ResourceGroup rg-logs-analyzer -SkipAuthSetup -AllowedIp 203.0.113.4/32

.EXAMPLE
  # An admin created the app registration for you
  ./deploy.ps1 -ResourceGroup rg-logs-analyzer -AuthClientId <guid> -AuthClientSecret <secret>
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ResourceGroup,
    [string] $Location = 'uksouth',
    [ValidateLength(2, 8)] [string] $NamePrefix = 'dla',

    # AI options. All optional: without any of them the site runs in pattern-library-only mode.
    [string] $AnthropicApiKey,
    [string] $AnthropicModel = 'claude-opus-5-5',
    [string] $AzureOpenAiEndpoint,
    [string] $AzureOpenAiDeployment,

    # Access control. You need Entra sign-in, an IP allow-list, or both.
    [string] $AuthClientId,
    [string] $AuthClientSecret,
    [string] $TenantId,
    [switch] $SkipAuthSetup,
    [string[]] $AllowedIp = @(),

    [int] $MaxUploadMb = 200
)

$ErrorActionPreference = 'Stop'
$appName = "Deployment Log Analyzer ($ResourceGroup)"
$root = (Resolve-Path (Join-Path (Join-Path $PSScriptRoot '..') '..')).Path

function Step($text) { Write-Host "`n==> $text" -ForegroundColor Cyan }
function Fail($text) { Write-Host "ERROR: $text" -ForegroundColor Red; exit 1 }
function AzCli {
    # Runs az, stops on failure, returns trimmed output.
    $out = & az @args
    if ($LASTEXITCODE -ne 0) { throw "az $($args[0..2] -join ' ') failed" }
    if ($null -eq $out) { return '' }
    return ($out -join "`n").Trim()
}

# --- 0. Checks ---------------------------------------------------------------------------
if (-not (Get-Command az -ErrorAction SilentlyContinue)) { Fail 'Azure CLI not found. Install it from https://aka.ms/installazurecli' }
$account = $null
try { $account = (& az account show 2>$null) | ConvertFrom-Json } catch { $account = $null }
if (-not $account) { Fail "Not signed in. Run 'az login' first." }
if (-not $TenantId) { $TenantId = $account.tenantId }
Write-Host "Subscription: $($account.name)  ($($account.id))"
Write-Host "Tenant:       $TenantId"

$haveAuth = [bool]$AuthClientId
if ($SkipAuthSetup -and -not $haveAuth -and $AllowedIp.Count -eq 0) {
    Fail 'Without sign-in the site would be open to anyone and could spend your API credit. Pass -AllowedIp, or remove -SkipAuthSetup.'
}
if ($haveAuth -and -not $AuthClientSecret) { Fail '-AuthClientId needs -AuthClientSecret as well.' }

if (-not $AnthropicApiKey -and -not $AzureOpenAiEndpoint) {
    # Re-running to update the code must not drop a key that is already stored.
    $existing = $null
    try { $existing = (& az containerapp secret show --name "$NamePrefix-api" --resource-group $ResourceGroup --secret-name anthropic-api-key --query value --output tsv 2>$null) } catch { $existing = $null }
    if ($LASTEXITCODE -eq 0 -and $existing) {
        $AnthropicApiKey = (($existing -join '')).Trim()
        Write-Host 'Keeping the API key already stored in Azure. Pass -AnthropicApiKey to replace it.'
    } else {
        $answer = Read-Host 'Anthropic API key (press Enter to run without AI)'
        if ($answer) { $AnthropicApiKey = $answer.Trim() }
    }
}

# --- 1. Infrastructure --------------------------------------------------------------------
Step "Resource group $ResourceGroup ($Location)"
AzCli group create --name $ResourceGroup --location $Location --output none | Out-Null

Step 'Registry, identity, logging and environment (first pass)'
$infra = AzCli deployment group create --resource-group $ResourceGroup --template-file (Join-Path $PSScriptRoot 'main.bicep') `
    --parameters namePrefix=$NamePrefix location=$Location deployApps=false `
    --query properties.outputs --output json | ConvertFrom-Json
$acr = $infra.acrName.value
$url = $infra.expectedUrl.value
$fqdn = ([Uri]$url).Host
Write-Host "Registry: $acr"
Write-Host "Site will be at: $url"

# --- 2. Sign-in ---------------------------------------------------------------------------
if (-not $haveAuth -and -not $SkipAuthSetup) {
    Step 'Setting up the Entra app registration for sign-in'
    try {
        $redirect = "$url/.auth/login/aad/callback"
        $found = $null
        try { $found = (& az ad app list --display-name $appName --query '[0].appId' --output tsv 2>$null) } catch { $found = $null }
        if ($found) {
            # Re-running: reuse the registration instead of creating a second one.
            $AuthClientId = (($found -join '')).Trim()
            Write-Host "Reusing the existing app registration $AuthClientId"
            AzCli ad app update --id $AuthClientId --web-redirect-uris $redirect --enable-id-token-issuance true --output none | Out-Null
        } else {
            $AuthClientId = AzCli ad app create --display-name $appName --sign-in-audience AzureADMyOrg `
                --web-redirect-uris $redirect --enable-id-token-issuance true --query appId --output tsv
            AzCli ad sp create --id $AuthClientId --output none | Out-Null
            Write-Host "Created app registration $AuthClientId"
        }
        # A fresh secret on every run. It goes straight into Azure and is never shown.
        $AuthClientSecret = AzCli ad app credential reset --id $AuthClientId --display-name 'container-apps' --years 1 --query password --output tsv
        $haveAuth = $true

        # Only people you assign can sign in.
        $spId = AzCli ad sp show --id $AuthClientId --query id --output tsv
        AzCli ad sp update --id $AuthClientId --set appRoleAssignmentRequired=true | Out-Null
        try {
            # Assign yourself so you are not locked out. Harmless if it already exists.
            $me = AzCli ad signed-in-user show --query id --output tsv
            $body = @{ principalId = $me; resourceId = $spId; appRoleId = '00000000-0000-0000-0000-000000000000' } | ConvertTo-Json -Compress
            $tmp = New-TemporaryFile
            Set-Content -Path $tmp -Value $body
            AzCli rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/appRoleAssignedTo" `
                --headers 'Content-Type=application/json' --body "@$tmp" --output none | Out-Null
            Remove-Item $tmp -Force
            Write-Host 'You have been assigned access.'
        } catch {
            Write-Host 'Could not assign you automatically (you may already be assigned). Check Enterprise applications > Users and groups.' -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Could not set up the app registration automatically: $($_.Exception.Message)" -ForegroundColor Yellow
        if ($AllowedIp.Count -eq 0) {
            Fail "Ask an admin to create the app registration (see README), then re-run with -AuthClientId and -AuthClientSecret. Or re-run with -SkipAuthSetup -AllowedIp <your address>."
        }
        Write-Host 'Continuing with the IP allow-list only.' -ForegroundColor Yellow
        $haveAuth = $false
    }
}

# --- 3. Images ----------------------------------------------------------------------------
$tag = (Get-Date -Format 'yyyyMMddHHmmss')
Step "Building images in the registry (tag $tag)"
function Build($image, $path, [string[]] $extra = @()) {
    # Called directly (not through AzCli) so the build log streams to the console.
    Write-Host "Building $image ..."
    & az acr build --registry $acr --image "${image}:$tag" @extra $path
    if ($LASTEXITCODE -ne 0) { Fail "Build of $image failed" }
}
Build 'dla-api'   (Join-Path $root 'backend')
Build 'dla-web'   (Join-Path $root 'frontend') @('--build-arg', 'NEXT_PUBLIC_API_URL=')
Build 'dla-proxy' (Join-Path (Join-Path $root 'deploy') 'proxy')

# --- 4. Apps ------------------------------------------------------------------------------
Step 'Deploying the apps'
# Secrets go through a temporary file so they never appear on a command line.
$params = @{
    '$schema'        = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
    contentVersion   = '1.0.0.0'
    parameters       = @{
        namePrefix            = @{ value = $NamePrefix }
        location              = @{ value = $Location }
        deployApps            = @{ value = $true }
        imageTag              = @{ value = $tag }
        maxUploadMb           = @{ value = $MaxUploadMb }
        anthropicApiKey       = @{ value = [string]$AnthropicApiKey }
        anthropicModel        = @{ value = $AnthropicModel }
        azureOpenAiEndpoint   = @{ value = [string]$AzureOpenAiEndpoint }
        azureOpenAiDeployment = @{ value = [string]$AzureOpenAiDeployment }
        authClientId          = @{ value = [string]$(if ($haveAuth) { $AuthClientId } else { '' }) }
        authClientSecret      = @{ value = [string]$(if ($haveAuth) { $AuthClientSecret } else { '' }) }
        tenantId              = @{ value = $TenantId }
        allowedIpCidrs        = @{ value = @($AllowedIp | ForEach-Object { if ($_ -match '/') { $_ } else { "$_/32" } }) }
    }
}
$paramFile = New-TemporaryFile
try {
    $params | ConvertTo-Json -Depth 6 | Set-Content -Path $paramFile
    AzCli deployment group create --resource-group $ResourceGroup --template-file (Join-Path $PSScriptRoot 'main.bicep') `
        --parameters "@$paramFile" --output none | Out-Null
} finally {
    Remove-Item $paramFile -Force -ErrorAction SilentlyContinue
}

# --- Done ---------------------------------------------------------------------------------
Step 'Done'
Write-Host "Open: $url" -ForegroundColor Green
if ($haveAuth) {
    Write-Host 'Sign-in is on. To let other people in, add them under Entra ID > Enterprise applications >'
    Write-Host "  '$appName' > Users and groups (or pass a security group)."
}
if ($AllowedIp.Count) { Write-Host "Only these addresses can reach the site: $($AllowedIp -join ', ')" }
if (-not $AnthropicApiKey -and -not $AzureOpenAiEndpoint) { Write-Host 'No AI provider configured: the site runs in pattern-library-only mode.' }
Write-Host "To remove everything later: az group delete --name $ResourceGroup"

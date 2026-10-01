// Deployment Log Analyzer on Azure Container Apps.
//
// Run it in two passes (deploy.ps1 does this for you):
//   1. deployApps = false  -> registry, identity, logging, Container Apps environment
//   2. build the three images in the registry
//   3. deployApps = true   -> the web, API and proxy apps
targetScope = 'resourceGroup'

@description('Short lower-case prefix used in resource names.')
@minLength(2)
@maxLength(8)
param namePrefix string = 'dla'

param location string = resourceGroup().location

@description('False for the first pass (no images exist yet), true once they are built.')
param deployApps bool = false

param imageTag string = 'latest'
param maxUploadMb int = 200

@description('Anthropic API key. Leave empty to run without it.')
@secure()
param anthropicApiKey string = ''
param anthropicModel string = 'claude-opus-5-5'

@description('Optional Azure OpenAI. The app signs in with its managed identity, so no key is needed.')
param azureOpenAiEndpoint string = ''
param azureOpenAiDeployment string = ''

@description('Entra app registration used for sign-in. Leave empty to rely on allowedIpCidrs only.')
param authClientId string = ''
@secure()
param authClientSecret string = ''
param tenantId string = tenant().tenantId

@description('If set, only these addresses can reach the site (for example "203.0.113.4/32").')
param allowedIpCidrs array = []

param logRetentionDays int = 30

var suffix = uniqueString(resourceGroup().id)
var acrName = toLower('${namePrefix}acr${suffix}')

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${namePrefix}-logs-${suffix}'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: logRetentionDays
  }
}

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: acrName
  location: location
  sku: { name: 'Basic' }
  properties: {
    adminUserEnabled: false
  }
}

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${namePrefix}-id'
  location: location
}

// AcrPull
var acrPullRole = '7f951dda-4ed3-4680-a7ca-43fe172d538d'
resource pull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: acr
  name: guid(acr.id, identity.id, acrPullRole)
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRole)
  }
}

resource env 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${namePrefix}-env'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logs.properties.customerId
        sharedKey: logs.listKeys().primarySharedKey
      }
    }
  }
}

module apps 'apps.bicep' = if (deployApps) {
  name: 'apps'
  dependsOn: [ pull ]
  params: {
    location: location
    prefix: namePrefix
    environmentId: env.id
    acrLoginServer: acr.properties.loginServer
    identityId: identity.id
    identityClientId: identity.properties.clientId
    imageTag: imageTag
    maxUploadMb: maxUploadMb
    anthropicApiKey: anthropicApiKey
    anthropicModel: anthropicModel
    azureOpenAiEndpoint: azureOpenAiEndpoint
    azureOpenAiDeployment: azureOpenAiDeployment
    authClientId: authClientId
    authClientSecret: authClientSecret
    tenantId: tenantId
    allowedIpCidrs: allowedIpCidrs
  }
}

output acrName string = acr.name
output acrLoginServer string = acr.properties.loginServer
output environmentDomain string = env.properties.defaultDomain
output identityName string = identity.name
output identityPrincipalId string = identity.properties.principalId
output expectedUrl string = 'https://${namePrefix}-proxy.${env.properties.defaultDomain}'

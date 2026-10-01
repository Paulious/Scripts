// The three container apps. Deployed by main.bicep once the images exist in the registry.

param location string
param prefix string
param environmentId string
param acrLoginServer string
param identityId string
param identityClientId string
param imageTag string
param maxUploadMb int

@secure()
param anthropicApiKey string
param anthropicModel string
param azureOpenAiEndpoint string
param azureOpenAiDeployment string

param authClientId string
@secure()
param authClientSecret string
param tenantId string
param allowedIpCidrs array

var aiAnthropic = !empty(anthropicApiKey)
var aiAzure = !empty(azureOpenAiEndpoint) && !empty(azureOpenAiDeployment)
var apiName = '${prefix}-api'
var webName = '${prefix}-web'
var proxyName = '${prefix}-proxy'

var registries = [
  {
    server: acrLoginServer
    identity: identityId
  }
]
var identity = {
  type: 'UserAssigned'
  userAssignedIdentities: {
    '${identityId}': {}
  }
}

// ---- API (internal only) ----------------------------------------------------------------
var apiSecrets = aiAnthropic ? [
  {
    name: 'anthropic-api-key'
    value: anthropicApiKey
  }
] : []

var apiEnvBase = [
  { name: 'LLM_PROVIDER', value: (aiAnthropic || aiAzure) ? 'auto' : 'none' }
  { name: 'MAX_UPLOAD_MB', value: string(maxUploadMb) }
  { name: 'CORS_ORIGINS', value: '[]' }
  { name: 'ANTHROPIC_MODEL', value: anthropicModel }
]
var apiEnvAnthropic = aiAnthropic ? [
  { name: 'ANTHROPIC_API_KEY', secretRef: 'anthropic-api-key' }
] : []
// No key is stored for Azure OpenAI: the app signs in with the managed identity.
var apiEnvAzure = aiAzure ? [
  { name: 'AZURE_OPENAI_ENDPOINT', value: azureOpenAiEndpoint }
  { name: 'AZURE_OPENAI_DEPLOYMENT', value: azureOpenAiDeployment }
  { name: 'AZURE_CLIENT_ID', value: identityClientId }
] : []

resource api 'Microsoft.App/containerApps@2024-03-01' = {
  name: apiName
  location: location
  identity: identity
  properties: {
    managedEnvironmentId: environmentId
    configuration: {
      registries: registries
      secrets: apiSecrets
      ingress: {
        external: false
        targetPort: 8000
        transport: 'auto'
        allowInsecure: true // internal hop from the proxy; TLS ends at the proxy
      }
    }
    template: {
      containers: [
        {
          name: 'api'
          image: '${acrLoginServer}/dla-api:${imageTag}'
          // Files are processed in memory, so give the API room. Large diagnostics packages are read one file at a time.
          resources: { cpu: json('2.0'), memory: '4Gi' }
          env: concat(apiEnvBase, apiEnvAnthropic, apiEnvAzure)
          probes: [
            {
              type: 'Liveness'
              httpGet: { path: '/api/health', port: 8000 }
              periodSeconds: 30
            }
          ]
        }
      ]
      scale: {
        minReplicas: 0
        maxReplicas: 3
        rules: [
          {
            name: 'http'
            http: { metadata: { concurrentRequests: '2' } }
          }
        ]
      }
    }
  }
}

// ---- Web (internal only) ------------------------------------------------------------------
resource web 'Microsoft.App/containerApps@2024-03-01' = {
  name: webName
  location: location
  identity: identity
  properties: {
    managedEnvironmentId: environmentId
    configuration: {
      registries: registries
      ingress: {
        external: false
        targetPort: 3000
        transport: 'auto'
        allowInsecure: true
      }
    }
    template: {
      containers: [
        {
          name: 'web'
          image: '${acrLoginServer}/dla-web:${imageTag}'
          resources: { cpu: json('0.5'), memory: '1Gi' }
        }
      ]
      scale: {
        minReplicas: 0
        maxReplicas: 2
        rules: [
          {
            name: 'http'
            http: { metadata: { concurrentRequests: '20' } }
          }
        ]
      }
    }
  }
}

// ---- Proxy (the only thing exposed to the internet) -----------------------------------------
var useAuth = !empty(authClientId)
var proxySecrets = useAuth ? [
  {
    name: 'auth-client-secret'
    value: authClientSecret
  }
] : []
var ipRules = [for (cidr, i) in allowedIpCidrs: {
  name: 'allow-${i}'
  action: 'Allow'
  ipAddressRange: cidr
}]

resource proxy 'Microsoft.App/containerApps@2024-03-01' = {
  name: proxyName
  location: location
  identity: identity
  properties: {
    managedEnvironmentId: environmentId
    configuration: {
      registries: registries
      secrets: proxySecrets
      ingress: {
        external: true
        targetPort: 8080
        transport: 'auto'
        allowInsecure: false
        ipSecurityRestrictions: ipRules
      }
    }
    template: {
      containers: [
        {
          name: 'proxy'
          image: '${acrLoginServer}/dla-proxy:${imageTag}'
          resources: { cpu: json('0.25'), memory: '0.5Gi' }
          env: [
            { name: 'API_HOST', value: apiName }
            { name: 'WEB_HOST', value: webName }
            { name: 'MAX_UPLOAD_MB', value: string(maxUploadMb) }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 2
      }
    }
  }
  dependsOn: [
    api
    web
  ]
}

// Microsoft Entra sign-in, handled by the platform in front of the proxy.
resource auth 'Microsoft.App/containerApps/authConfigs@2024-03-01' = if (useAuth) {
  parent: proxy
  name: 'current'
  properties: {
    platform: { enabled: true }
    globalValidation: {
      unauthenticatedClientAction: 'RedirectToLoginPage'
      redirectToProvider: 'azureactivedirectory'
      excludedPaths: [ '/healthz' ]
    }
    identityProviders: {
      azureActiveDirectory: {
        enabled: true
        registration: {
          openIdIssuer: '${environment().authentication.loginEndpoint}${tenantId}/v2.0'
          clientId: authClientId
          clientSecretSettingName: 'auth-client-secret'
        }
        validation: {
          allowedAudiences: [ authClientId ]
        }
      }
    }
    login: { preserveUrlFragmentsForLogins: true }
  }
}

output proxyFqdn string = proxy.properties.configuration.ingress.fqdn

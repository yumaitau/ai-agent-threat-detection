// Yuma AI Agent Threat Detection - unified Microsoft Sentinel deployment (Bicep).
// Deploys into an existing Log Analytics workspace with Microsoft Sentinel enabled:
//   - AI agent register infrastructure (AIAgentRegister_CL table, direct-ingestion DCR, watchlists, saved functions)
//   - Yuma AI Agent Register and ISM Evidence workbook
//   - Scheduled analytics rules (D04, D05, D07, D08, D10, D14) - disabled by default
//   - Hunting queries (D01, D06, D09, D13, D15)
// UNVALIDATED against a live workspace; checked offline with bicep build and KQL semantic binding.

@description('Name of the existing Log Analytics workspace with Microsoft Sentinel enabled.')
param workspaceName string

@description('Azure region matching the existing Log Analytics workspace (must match the workspace region for the DCR).')
param location string = resourceGroup().location

@description('Deploy the AI agent register table, DCR, watchlists and saved workspace functions.')
param deployRegisterInfrastructure bool = true

@description('Deploy the Yuma AI Agent Register and ISM Evidence Sentinel workbook.')
param deployWorkbook bool = true

@description('Deploy the six scheduled Microsoft Sentinel analytics rules (D04, D05, D07, D08, D10, D14).')
param deployAnalyticsRules bool = true

@description('Deploy the five Microsoft Sentinel hunting queries (D01, D06, D09, D13, D15).')
param deployHuntingQueries bool = true

@description('Enable analytics rules immediately on deployment. Keep false to tune thresholds before alerting.')
param enableAnalyticsRules bool = false

@description('Interactive retention for AIAgentRegister_CL in days (minimum 183 days to retain six-monthly ISM-2138 review records).')
@minValue(183)
@maxValue(730)
param retentionInDays int = 365

@description('Total retention (interactive plus long-term) for AIAgentRegister_CL in days.')
@minValue(183)
@maxValue(4383)
param totalRetentionInDays int = 2555

@description('Name for the direct-ingestion Data Collection Rule writing to AIAgentRegister_CL. Leave blank for a workspace-scoped default name.')
param dcrName string = ''

@description('Display name for the Microsoft Sentinel workbook.')
param workbookDisplayName string = 'Yuma AI Agent Register and ISM Evidence'

var columns = loadJsonContent('../register/AIAgentRegister_CL.columns.json')
var streamColumns = [for c in columns: {
  name: c.name
  type: c.type
}]
var functionCategory = 'Yuma AI Agent Pack'

resource ws 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

var effectiveDcrName = empty(dcrName) ? 'dcr-yuma-ai-agent-register-${uniqueString(ws.id)}' : dcrName

// ---------------- Register infrastructure ----------------

resource registerTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = if (deployRegisterInfrastructure) {
  parent: ws
  name: 'AIAgentRegister_CL'
  properties: {
    retentionInDays: retentionInDays
    totalRetentionInDays: totalRetentionInDays
    schema: {
      name: 'AIAgentRegister_CL'
      columns: columns
    }
  }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = if (deployRegisterInfrastructure) {
  name: effectiveDcrName
  location: location
  kind: 'Direct'
  properties: {
    streamDeclarations: {
      'Custom-AIAgentRegister': {
        columns: streamColumns
      }
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: ws.id
          name: 'sentinelWorkspace'
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Custom-AIAgentRegister'
        ]
        destinations: [
          'sentinelWorkspace'
        ]
        transformKql: 'source | extend TimeGenerated = iff(isnull(TimeGenerated), now(), TimeGenerated)'
        outputStream: 'Custom-AIAgentRegister_CL'
      }
    ]
  }
  dependsOn: [
    registerTable
  ]
}

resource approvedWatchlist 'Microsoft.SecurityInsights/watchlists@2023-02-01' = if (deployRegisterInfrastructure) {
  scope: ws
  name: 'YumaAIRegisterApproved'
  properties: {
    displayName: 'Yuma AI Register - approved agents and apps'
    description: 'Service principals approved through PB2. Suppresses D04 and D05. Maintained by PB2; remove the placeholder row after the first approval.'
    provider: 'Yuma IT'
    source: 'watchlist-YumaAIRegisterApproved.csv'
    itemsSearchKey: 'ServicePrincipalId'
    rawContent: loadTextContent('../register/watchlist-YumaAIRegisterApproved.csv')
    contentType: 'text/csv'
    numberOfLinesToSkip: 0
  }
}

resource ismWatchlist 'Microsoft.SecurityInsights/watchlists@2023-02-01' = if (deployRegisterInfrastructure) {
  scope: ws
  name: 'YumaISMControlMap'
  properties: {
    displayName: 'Yuma ISM control map (agentic AI)'
    description: 'ISM-2133 to 2140 and ISM-2156 to 2159 control text (ASD ISM September 2026) mapped to pack evidence.'
    provider: 'Yuma IT'
    source: 'watchlist-YumaISMControlMap.csv'
    itemsSearchKey: 'ControlId'
    rawContent: loadTextContent('../register/watchlist-YumaISMControlMap.csv')
    contentType: 'text/csv'
    numberOfLinesToSkip: 0
  }
}

resource fnRegister 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = if (deployRegisterInfrastructure) {
  parent: ws
  name: 'yuma-fn-YumaAIRegister'
  properties: {
    category: functionCategory
    displayName: 'YumaAIRegister'
    functionAlias: 'YumaAIRegister'
    query: loadTextContent('../../functions/YumaAIRegister.kql')
    version: 2
  }
  dependsOn: [
    registerTable
  ]
}

resource fnControls 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = if (deployRegisterInfrastructure) {
  parent: ws
  name: 'yuma-fn-YumaISMControlStatus'
  properties: {
    category: functionCategory
    displayName: 'YumaISMControlStatus'
    functionAlias: 'YumaISMControlStatus'
    query: loadTextContent('../../functions/YumaISMControlStatus.kql')
    version: 2
  }
  dependsOn: [
    fnRegister
    ismWatchlist
  ]
}

resource fnRegisterCsv 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = if (deployRegisterInfrastructure) {
  parent: ws
  name: 'yuma-fn-YumaEvidenceRegisterCsv'
  properties: {
    category: functionCategory
    displayName: 'YumaEvidenceRegisterCsv'
    functionAlias: 'YumaEvidenceRegisterCsv'
    query: loadTextContent('../../functions/YumaEvidenceRegisterCsv.kql')
    version: 2
  }
  dependsOn: [
    fnRegister
  ]
}

resource fnControlsCsv 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = if (deployRegisterInfrastructure) {
  parent: ws
  name: 'yuma-fn-YumaEvidenceControlsCsv'
  properties: {
    category: functionCategory
    displayName: 'YumaEvidenceControlsCsv'
    functionAlias: 'YumaEvidenceControlsCsv'
    query: loadTextContent('../../functions/YumaEvidenceControlsCsv.kql')
    version: 2
  }
  dependsOn: [
    fnControls
  ]
}

resource fnMarkdown 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = if (deployRegisterInfrastructure) {
  parent: ws
  name: 'yuma-fn-YumaEvidenceMarkdown'
  properties: {
    category: functionCategory
    displayName: 'YumaEvidenceMarkdown'
    functionAlias: 'YumaEvidenceMarkdown'
    query: loadTextContent('../../functions/YumaEvidenceMarkdown.kql')
    version: 2
  }
  dependsOn: [
    fnControls
  ]
}

// ---------------- Workbook ----------------

resource workbook 'Microsoft.Insights/workbooks@2022-04-01' = if (deployWorkbook) {
  name: guid(ws.id, 'yuma-ai-agent-register-workbook')
  location: location
  kind: 'shared'
  properties: {
    displayName: workbookDisplayName
    category: 'sentinel'
    sourceId: ws.id
    version: 'Notebook/1.0'
    serializedData: replace(loadTextContent('../workbook/yuma-ai-agent-register.workbook.json'), '__WORKSPACE_RESOURCE_ID__', ws.id)
  }
  dependsOn: [
    fnRegister
    fnControls
  ]
}

// ---------------- Scheduled analytics rules ----------------

resource ruleD04 'Microsoft.SecurityInsights/alertRules@2023-02-01' = if (deployAnalyticsRules) {
  scope: ws
  name: guid(ws.id, 'yuma-aia-d04')
  kind: 'Scheduled'
  properties: {
    displayName: 'Yuma AIA-D04 High-risk Graph permission granted to AI agent or AI app'
    description: 'High-risk Microsoft Graph permission granted to an Entra agent identity, an AI-named app, or self-granted by an app. Maps to ISM-2156, ISM-2137, ISM-2138, ISM-2139.'
    severity: 'Medium'
    enabled: enableAnalyticsRules
    query: loadTextContent('../../detections/D04-HighRiskGraphPermissionToAIAgentOrApp.kql')
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    tactics: [
      'PrivilegeEscalation'
      'Persistence'
    ]
    techniques: [
      'T1098'
    ]
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'InitiatedByUpn' }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          { identifier: 'Address', columnName: 'InitiatedByIp' }
        ]
      }
      {
        entityType: 'CloudApplication'
        fieldMappings: [
          { identifier: 'Name', columnName: 'ClientAppName' }
        ]
      }
    ]
    customDetails: {
      ClientSpId: 'ClientSpId'
      ClientAppName: 'ClientAppName'
      Permissions: 'GrantedPermissions'
      AgentType: 'TargetAgentType'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Yuma AIA-D04: {{ClientAppName}} granted high-risk Graph permission'
      alertSeverityColumnName: 'Severity'
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
        groupByEntities: []
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
  }
  dependsOn: [
    approvedWatchlist
  ]
}

resource ruleD05 'Microsoft.SecurityInsights/alertRules@2023-02-01' = if (deployAnalyticsRules) {
  scope: ws
  name: guid(ws.id, 'yuma-aia-d05')
  kind: 'Scheduled'
  properties: {
    displayName: 'Yuma AIA-D05 New AI app consent (user or admin), first seen'
    description: 'Detects first-seen admin or user OAuth consent to an AI agent or AI-named application in Entra ID. Maps to ISM-2134, ISM-2135, ISM-2137, ISM-2138, ISM-2139.'
    severity: 'Low'
    enabled: enableAnalyticsRules
    query: loadTextContent('../../detections/D05-NewAIAppConsent.kql')
    queryFrequency: 'PT1H'
    queryPeriod: 'P14D'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    tactics: [
      'CredentialAccess'
      'Persistence'
    ]
    techniques: [
      'T1528'
    ]
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'ConsentedByUpn' }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          { identifier: 'Address', columnName: 'ConsentedByIp' }
        ]
      }
      {
        entityType: 'CloudApplication'
        fieldMappings: [
          { identifier: 'Name', columnName: 'AppName' }
        ]
      }
    ]
    customDetails: {
      AppSpId: 'AppSpId'
      AppName: 'AppName'
      ConsentType: 'ConsentType'
      Scopes: 'Scopes'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Yuma AIA-D05: new AI app consent for {{AppName}}'
      alertSeverityColumnName: 'Severity'
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
        groupByEntities: []
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
  }
  dependsOn: [
    approvedWatchlist
  ]
}

resource ruleD07 'Microsoft.SecurityInsights/alertRules@2023-02-01' = if (deployAnalyticsRules) {
  scope: ws
  name: guid(ws.id, 'yuma-aia-d07')
  kind: 'Scheduled'
  properties: {
    displayName: 'Yuma AIA-D07 Agent identity or AI service principal sign-in anomaly'
    description: 'Detects an Entra agent identity or AI service principal signing in from a new ASN or IP, to a new resource, with a new credential type, or with a burst of failures against a 14-day baseline. Maps to ISM-2133, ISM-2136, ISM-2141, ISM-2142, ISM-2148.'
    severity: 'Medium'
    enabled: enableAnalyticsRules
    query: loadTextContent('../../detections/D07-AgentIdentitySignInAnomaly.kql')
    queryFrequency: 'PT1H'
    queryPeriod: 'P14D'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    tactics: [
      'InitialAccess'
      'DefenseEvasion'
      'CredentialAccess'
    ]
    techniques: [
      'T1078'
      'T1550'
    ]
    entityMappings: [
      {
        entityType: 'IP'
        fieldMappings: [
          { identifier: 'Address', columnName: 'IPAddress' }
        ]
      }
      {
        entityType: 'CloudApplication'
        fieldMappings: [
          { identifier: 'Name', columnName: 'ServicePrincipalName' }
        ]
      }
    ]
    customDetails: {
      ServicePrincipalId: 'ServicePrincipalId'
      AppId: 'AppId'
      AgentType: 'AgentType'
      Reasons: 'Reasons'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Yuma AIA-D07: sign-in anomaly for {{ServicePrincipalName}}'
      alertSeverityColumnName: 'Severity'
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
        groupByEntities: []
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
  }
}

resource ruleD08 'Microsoft.SecurityInsights/alertRules@2023-02-01' = if (deployAnalyticsRules) {
  scope: ws
  name: guid(ws.id, 'yuma-aia-d08')
  kind: 'Scheduled'
  properties: {
    displayName: 'Yuma AIA-D08 Agent or AI app Microsoft Graph data-access burst'
    description: 'Detects an AI agent or AI app exceeding its 14-day hourly baseline for sensitive Microsoft Graph API calls (mail, files, sites, chats, directory, or MCP Server for Enterprise). Maps to ISM-2157, ISM-2159.'
    severity: 'Medium'
    enabled: enableAnalyticsRules
    query: loadTextContent('../../detections/D08-AgentGraphDataAccessBurst.kql')
    queryFrequency: 'PT1H'
    queryPeriod: 'P14D'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    tactics: [
      'Collection'
      'Discovery'
    ]
    techniques: [
      'T1114'
      'T1530'
      'T1087'
    ]
    entityMappings: [
      {
        entityType: 'CloudApplication'
        fieldMappings: [
          { identifier: 'Name', columnName: 'AppName' }
        ]
      }
    ]
    customDetails: {
      AppId: 'AppId'
      ServicePrincipalId: 'ServicePrincipalId'
      Requests: 'Requests'
      DistinctTargetUsers: 'DistinctTargetUsers'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Yuma AIA-D08: Graph data-access burst by {{AppName}}'
      alertSeverityColumnName: 'Severity'
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
        groupByEntities: []
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
  }
}

resource ruleD10 'Microsoft.SecurityInsights/alertRules@2023-02-01' = if (deployAnalyticsRules) {
  scope: ws
  name: guid(ws.id, 'yuma-aia-d10')
  kind: 'Scheduled'
  properties: {
    displayName: 'Yuma AIA-D10 Prompt-injection or jailbreak alert followed by exfiltration activity'
    description: 'Correlates Defender XDR prompt-injection alerts or Copilot jailbreak events with exfiltration-like CloudAppEvents activity by the same user within two hours. Maps to ISM-2158, ISM-1924, ISM-2113.'
    severity: 'Medium'
    enabled: enableAnalyticsRules
    query: loadTextContent('../../detections/D10-PromptInjectionThenExfiltration.kql')
    queryFrequency: 'PT1H'
    queryPeriod: 'PT3H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    tactics: [
      'Exfiltration'
      'Collection'
    ]
    techniques: [
      'T1567'
      'T1530'
      'T1114'
    ]
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'AccountUpn' }
          { identifier: 'AadUserId', columnName: 'AccountObjectId' }
        ]
      }
    ]
    customDetails: {
      TriggerSource: 'TriggerSource'
      TriggerId: 'TriggerId'
      ExfilEvents: 'ExfilEvents'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Yuma AIA-D10: post-injection exfiltration activity for {{AccountUpn}}'
      alertSeverityColumnName: 'Severity'
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
        groupByEntities: []
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
  }
}

resource ruleD14 'Microsoft.SecurityInsights/alertRules@2023-02-01' = if (deployAnalyticsRules) {
  scope: ws
  name: guid(ws.id, 'yuma-aia-d14')
  kind: 'Scheduled'
  properties: {
    displayName: 'Yuma AIA-D14 AI-speed exploitation burst against App Gateway WAF'
    description: 'One client IP tripped many distinct WAF rules across many URIs within 10 minutes, typical of automated or LLM-driven exploit tooling. Maps to ISM-2116 and Essential Eight patch applications.'
    severity: 'Medium'
    enabled: enableAnalyticsRules
    query: loadTextContent('../../detections/D14-AISpeedExploitationBurst.kql')
    queryFrequency: 'PT10M'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    tactics: [
      'InitialAccess'
      'Reconnaissance'
    ]
    techniques: [
      'T1190'
      'T1595'
    ]
    entityMappings: [
      {
        entityType: 'IP'
        fieldMappings: [
          { identifier: 'Address', columnName: 'ClientIp' }
        ]
      }
    ]
    customDetails: {
      DistinctRules: 'DistinctRules'
      DistinctUris: 'DistinctUris'
      ClaimsAIAgent: 'ClaimsAIAgent'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Yuma AIA-D14: exploit burst from {{ClientIp}}'
      alertSeverityColumnName: 'Severity'
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
        groupByEntities: []
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
  }
}

// ---------------- Hunting queries ----------------

resource huntD01 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = if (deployHuntingQueries) {
  parent: ws
  name: 'yuma-hunt-D01-shadow-ai-non-browser'
  properties: {
    category: 'Hunting Queries'
    displayName: 'Yuma AIA-D01 Shadow AI: non-browser process calling AI model APIs'
    query: loadTextContent('../../detections/D01-ShadowAI-NonBrowserProcessToAIAPI.kql')
    version: 2
    tags: [
      { name: 'description', value: 'Hunts for non-browser endpoint processes connecting to third-party AI model APIs via DeviceNetworkEvents.' }
      { name: 'tactics', value: 'Exfiltration,CommandAndControl' }
      { name: 'techniques', value: 'T1567' }
    ]
  }
}

resource huntD06 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = if (deployHuntingQueries) {
  parent: ws
  name: 'yuma-hunt-D06-agent-static-secret'
  properties: {
    category: 'Hunting Queries'
    displayName: 'Yuma AIA-D06 Agent identities on static client secrets'
    query: loadTextContent('../../detections/D06-AgentIdentityStaticSecret.kql')
    version: 2
    tags: [
      { name: 'description', value: 'Hunts for Entra agent identities and AI service principals authenticating with static client secrets.' }
      { name: 'tactics', value: 'CredentialAccess' }
      { name: 'techniques', value: 'T1552' }
    ]
  }
}

resource huntD09 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = if (deployHuntingQueries) {
  parent: ws
  name: 'yuma-hunt-D09-agent-register-export'
  properties: {
    category: 'Hunting Queries'
    displayName: 'Yuma AIA-D09 AI agent register review with ISM gap flags'
    query: loadTextContent('../../detections/D09-AgentRegisterExport-ISM2135.kql')
    version: 2
    tags: [
      { name: 'description', value: 'Reviews AgentsInfo inventory records with ISM-2133 and ISM-2135 completeness gap flags.' }
      { name: 'tactics', value: 'Discovery' }
    ]
  }
}

resource huntD13 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = if (deployHuntingQueries) {
  parent: ws
  name: 'yuma-hunt-D13-ai-crawler-mcp-probe'
  properties: {
    category: 'Hunting Queries'
    displayName: 'Yuma AIA-D13 AI crawler and MCP endpoint probing'
    query: loadTextContent('../../detections/D13-AIAgentCrawlerAndMcpProbe.kql')
    version: 2
    tags: [
      { name: 'description', value: 'Hunts Application Gateway access logs for AI crawler user agents or probes against MCP and LLM endpoints.' }
      { name: 'tactics', value: 'Reconnaissance' }
      { name: 'techniques', value: 'T1595,T1593' }
    ]
  }
}

resource huntD15 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = if (deployHuntingQueries) {
  parent: ws
  name: 'yuma-hunt-D15-agentic-mcp-sensitive'
  properties: {
    category: 'Hunting Queries'
    displayName: 'Yuma AIA-D15 Agentic traffic invoking sensitive MCP primitives or new destinations'
    query: loadTextContent('../../detections/D15-AgenticMcpSensitivePrimitive.kql')
    version: 2
    tags: [
      { name: 'description', value: 'Hunts Entra Global Secure Access NetworkAccessTraffic logs for sensitive MCP primitives or newly observed MCP destinations.' }
      { name: 'tactics', value: 'Impact,Exfiltration' }
      { name: 'techniques', value: 'T1485,T1567' }
    ]
  }
}

output workspaceResourceId string = ws.id
output dcrResourceId string = deployRegisterInfrastructure ? dcr.id : ''
output dcrImmutableId string = deployRegisterInfrastructure ? (dcr.?properties.?immutableId ?? '') : ''
output logsIngestionEndpoint string = deployRegisterInfrastructure ? (dcr.?properties.?endpoints.?logsIngestion ?? '') : ''
output workbookId string = deployWorkbook ? workbook.id : ''
output ruleD04ResourceId string = deployAnalyticsRules ? ruleD04.id : ''
output ruleD14ResourceId string = deployAnalyticsRules ? ruleD14.id : ''

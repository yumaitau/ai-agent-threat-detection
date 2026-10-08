// Yuma AI agent register infrastructure, all inside the customer's Sentinel workspace. UNVALIDATED: type-checked
// with bicep build only, never deployed.
//   - custom table AIAgentRegister_CL (Logs Ingestion API target)
//   - direct-ingestion DCR with stream Custom-AIAgentRegister (writers: PB2, PB4)
//   - watchlists YumaAIRegisterApproved (suppression list for D04/D05) and YumaISMControlMap (ISM-2133..2140, 2156..2159)
//   - saved functions YumaAIRegister, YumaISMControlStatus, YumaEvidenceRegisterCsv, YumaEvidenceControlsCsv, YumaEvidenceMarkdown
// References:
//   https://learn.microsoft.com/en-us/azure/azure-monitor/logs/tutorial-logs-ingestion-api
//   https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview
//   https://learn.microsoft.com/en-us/rest/api/securityinsights/watchlists/create-or-update

@description('Log Analytics workspace name with Microsoft Sentinel enabled')
param workspaceName string
param location string = resourceGroup().location
@description('Interactive retention for the register table, in days')
param retentionInDays int = 365
@description('Total retention (interactive + long-term) for the register table, in days. Set to your records policy.')
param totalRetentionInDays int = 2555
param dcrName string = 'dcr-yuma-ai-agent-register'

var columns = loadJsonContent('../register/AIAgentRegister_CL.columns.json')
// DCR stream declarations accept: string, int, long, real, boolean, datetime, dynamic (no descriptions)
var streamColumns = [for c in columns: {
  name: c.name
  type: c.type
}]
var functionCategory = 'Yuma AI Agent Pack'

resource ws 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

resource registerTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
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

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dcrName
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

resource approvedWatchlist 'Microsoft.SecurityInsights/watchlists@2023-02-01' = {
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

resource ismWatchlist 'Microsoft.SecurityInsights/watchlists@2023-02-01' = {
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

resource fnRegister 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = {
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

resource fnControls 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = {
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

resource fnRegisterCsv 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = {
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

resource fnControlsCsv 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = {
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

resource fnMarkdown 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = {
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

output dcrResourceId string = dcr.id
output dcrImmutableId string = dcr.properties.immutableId
output logsIngestionEndpoint string = dcr.properties.endpoints.logsIngestion
output streamName string = 'Custom-AIAgentRegister'

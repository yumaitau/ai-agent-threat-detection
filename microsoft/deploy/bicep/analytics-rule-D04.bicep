// Yuma AIA-D04 analytics rule (Bicep). UNVALIDATED against a live workspace; type-checked with bicep build only.
@description('Log Analytics workspace name with Microsoft Sentinel enabled')
param workspaceName string
@description('Rule GUID. Pin a fixed value for idempotent redeploys.')
param ruleId string = newGuid()
param enabled bool = false

resource ws 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

resource rule 'Microsoft.SecurityInsights/alertRules@2023-02-01' = {
  scope: ws
  name: ruleId
  kind: 'Scheduled'
  properties: {
    displayName: 'Yuma AIA-D04 High-risk Graph permission granted to AI agent or AI app'
    description: 'High-risk Microsoft Graph permission granted to an Entra agent identity, an AI-named app, or self-granted by an app. Maps to ISM-2156, ISM-2137, ISM-2138, ISM-2139.'
    severity: 'Medium'
    enabled: enabled
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
}

output ruleResourceId string = rule.id

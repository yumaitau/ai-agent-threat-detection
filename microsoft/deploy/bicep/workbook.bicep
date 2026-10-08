// Yuma AI Agent Register and ISM Evidence workbook. UNVALIDATED: type-checked with bicep build only.
param workspaceName string
param location string = resourceGroup().location
param workbookDisplayName string = 'Yuma AI Agent Register and ISM Evidence'

resource ws 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

resource workbook 'Microsoft.Insights/workbooks@2022-04-01' = {
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
}

output workbookId string = workbook.id

#!/usr/bin/env python3
"""Generate ARM templates for the Yuma AI/agent pack from the .kql sources.
Outputs: deploy/analytics-rule-D04.json, deploy/analytics-rule-D14.json, deploy/playbook-PB1-agent-containment.json,
deploy/automation-rule-D04-PB1.json, deploy/playbook-PB4-register-sync.json, deploy/playbook-PB5-ism-evidence-export.json.
Register infrastructure and the workbook are compiled from Bicep (deploy/bicep). Templates are syntactically valid JSON
but NOT deployed or tested."""
import json, pathlib, re
root = pathlib.Path(__file__).resolve().parent.parent
det = root / "detections"
out = root / "deploy"

def kql(name):
    text = (det / name).read_text()
    # strip leading comment header so the rule query stays lean; keep inline comments
    lines = text.splitlines()
    while lines and lines[0].startswith("//"):
        lines.pop(0)
    return "\n".join(lines).strip() + "\n"

def rule_template(rule_guid_seed, display, description, severity, query, freq, period, tactics, techniques,
                  entity_mappings, custom_details, name_format):
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "0.1.0.0",
        "metadata": {"author": "Yuma IT", "comments": "UNVALIDATED skeleton. Test in a non-production workspace first."},
        "parameters": {
            "workspace": {"type": "string", "metadata": {"description": "Log Analytics workspace name with Microsoft Sentinel enabled"}},
            "ruleId": {"type": "string", "defaultValue": f"[newGuid()]", "metadata": {"description": "Rule GUID; set a fixed value to make redeploys idempotent"}},
            "enabled": {"type": "bool", "defaultValue": False}
        },
        "resources": [{
            "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
            "apiVersion": "2023-02-01",
            "name": "[concat(parameters('workspace'), '/Microsoft.SecurityInsights/', parameters('ruleId'))]",
            "kind": "Scheduled",
            "properties": {
                "displayName": display,
                "description": description,
                "severity": severity,
                "enabled": "[parameters('enabled')]",
                "query": query,
                "queryFrequency": freq,
                "queryPeriod": period,
                "triggerOperator": "GreaterThan",
                "triggerThreshold": 0,
                "suppressionDuration": "PT5H",
                "suppressionEnabled": False,
                "tactics": tactics,
                "techniques": techniques,
                "entityMappings": entity_mappings,
                "customDetails": custom_details,
                "alertDetailsOverride": {"alertDisplayNameFormat": name_format, "alertSeverityColumnName": "Severity"},
                "eventGroupingSettings": {"aggregationKind": "AlertPerResult"},
                "incidentConfiguration": {
                    "createIncident": True,
                    "groupingConfiguration": {
                        "enabled": True, "reopenClosedIncident": False, "lookbackDuration": "PT5H",
                        "matchingMethod": "AllEntities", "groupByEntities": [], "groupByAlertDetails": [], "groupByCustomDetails": []
                    }
                }
            }
        }],
        "outputs": {"ruleResourceId": {"type": "string", "value": "[resourceId('Microsoft.OperationalInsights/workspaces/providers/alertRules', parameters('workspace'), 'Microsoft.SecurityInsights', parameters('ruleId'))]"}}
    }

d04 = rule_template(
    "D04", "Yuma AIA-D04 High-risk Graph permission granted to AI agent or AI app",
    "A high-risk Microsoft Graph application or delegated permission was granted to a service principal that is an Entra agent identity, has an AI vendor name, or granted itself the permission. Maps to ISM-2156, ISM-2137, ISM-2138, ISM-2139.",
    "Medium", kql("D04-HighRiskGraphPermissionToAIAgentOrApp.kql"), "PT1H", "PT1H",
    ["PrivilegeEscalation", "Persistence"], ["T1098"],
    [
        {"entityType": "Account", "fieldMappings": [{"identifier": "FullName", "columnName": "InitiatedByUpn"}]},
        {"entityType": "IP", "fieldMappings": [{"identifier": "Address", "columnName": "InitiatedByIp"}]},
        {"entityType": "CloudApplication", "fieldMappings": [{"identifier": "Name", "columnName": "ClientAppName"}]}
    ],
    {"ClientSpId": "ClientSpId", "ClientAppName": "ClientAppName", "Permissions": "GrantedPermissions", "AgentType": "TargetAgentType"},
    "Yuma AIA-D04: {{ClientAppName}} granted high-risk Graph permission")
d14 = rule_template(
    "D14", "Yuma AIA-D14 AI-speed exploitation burst against App Gateway WAF",
    "One client IP tripped many distinct WAF rules across many URIs within 10 minutes, typical of automated or LLM-driven exploit tooling. Maps to ISM-2116 and Essential Eight patch applications.",
    "Medium", kql("D14-AISpeedExploitationBurst.kql"), "PT10M", "PT1H",
    ["InitialAccess", "Reconnaissance"], ["T1190", "T1595"],
    [{"entityType": "IP", "fieldMappings": [{"identifier": "Address", "columnName": "ClientIp"}]}],
    {"DistinctRules": "DistinctRules", "DistinctUris": "DistinctUris", "ClaimsAIAgent": "ClaimsAIAgent"},
    "Yuma AIA-D14: exploit burst from {{ClientIp}}")

# ---------------- PB1 playbook ----------------
graph = "https://graph.microsoft.com"
msi = {"type": "ManagedServiceIdentity", "audience": graph}
sentinel_conn = {"connection": {"name": "@parameters('$connections')['azuresentinel']['connectionId']"}}
teams_conn = {"connection": {"name": "@parameters('$connections')['teams']['connectionId']"}}
def comment(msg, after):
    return {"type": "ApiConnection", "runAfter": after,
            "inputs": {"host": sentinel_conn, "method": "post", "path": "/Incidents/Comment",
                       "body": {"incidentArmId": "@triggerBody()?['object']?['id']", "message": msg}}}
card = {
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
    "body": [
        {"type": "TextBlock", "size": "Large", "weight": "Bolder", "wrap": True, "text": "AI agent permission alert"},
        {"type": "TextBlock", "wrap": True, "text": "Incident @{triggerBody()?['object']?['properties']?['incidentNumber']}: @{triggerBody()?['object']?['properties']?['title']}"},
        {"type": "FactSet", "facts": [
            {"title": "App", "value": "@{body('Get_service_principal')?['displayName']}"},
            {"title": "App ID", "value": "@{body('Get_service_principal')?['appId']}"},
            {"title": "Publisher verified", "value": "@{body('Get_service_principal')?['verifiedPublisher']?['displayName']}"},
            {"title": "Owners", "value": "@{join(body('Select_owner_upns'), ', ')}"},
            {"title": "App role assignments", "value": "@{length(body('Get_app_role_assignments')?['value'])}"}]},
        {"type": "TextBlock", "wrap": True, "text": "[Open incident](@{triggerBody()?['object']?['properties']?['incidentUrl']})"},
        {"type": "Input.ChoiceSet", "id": "decision", "style": "expanded", "value": "keep", "choices": [
            {"title": "Disable the service principal (stops new tokens)", "value": "disable"},
            {"title": "Keep enabled and monitor", "value": "keep"},
            {"title": "Expected, close as benign", "value": "benign"}]}
    ],
    "actions": [{"type": "Action.Submit", "title": "Submit"}]
}
actions = {
    "Init_SpId": {"type": "InitializeVariable", "runAfter": {},
        "inputs": {"variables": [{"name": "SpId", "type": "string",
            "value": "@{first(json(first(triggerBody()?['object']?['properties']?['Alerts'])?['properties']?['additionalData']?['Custom Details'])?['ClientSpId'])}"}]}},
    "Get_service_principal": {"type": "Http", "runAfter": {"Init_SpId": ["Succeeded"]},
        "inputs": {"method": "GET", "uri": f"{graph}/v1.0/servicePrincipals/@{{variables('SpId')}}?$select=id,appId,displayName,accountEnabled,verifiedPublisher,appOwnerOrganizationId,servicePrincipalType,tags", "authentication": msi}},
    "Get_owners": {"type": "Http", "runAfter": {"Get_service_principal": ["Succeeded"]},
        "inputs": {"method": "GET", "uri": f"{graph}/v1.0/servicePrincipals/@{{variables('SpId')}}/owners?$select=id,displayName,userPrincipalName", "authentication": msi}},
    "Select_owner_upns": {"type": "Select", "runAfter": {"Get_owners": ["Succeeded"]},
        "inputs": {"from": "@body('Get_owners')?['value']", "select": "@coalesce(item()?['userPrincipalName'], item()?['displayName'])"}},
    "Get_app_role_assignments": {"type": "Http", "runAfter": {"Select_owner_upns": ["Succeeded"]},
        "inputs": {"method": "GET", "uri": f"{graph}/v1.0/servicePrincipals/@{{variables('SpId')}}/appRoleAssignments", "authentication": msi}},
    "Comment_enrichment": comment("<p>Yuma PB1 enrichment. App: @{body('Get_service_principal')?['displayName']} (appId @{body('Get_service_principal')?['appId']}). Enabled: @{body('Get_service_principal')?['accountEnabled']}. Owners: @{join(body('Select_owner_upns'), ', ')}. App role assignments: @{length(body('Get_app_role_assignments')?['value'])}. Awaiting human decision (ISM-2113).</p>",
                                  {"Get_app_role_assignments": ["Succeeded"]}),
    "Post_adaptive_card_and_wait_for_a_response": {"type": "ApiConnectionWebhook", "runAfter": {"Comment_enrichment": ["Succeeded"]},
        "inputs": {"host": teams_conn,
                   "path": "/v1.0/teams/conversation/gatherinput/poster/Flow bot/location/@{encodeURIComponent('Channel')}/$subscriptions",
                   "body": {"notificationUrl": "@{listCallbackUrl()}",
                            "body": {"messageBody": json.dumps(card), "updateMessage": "Thanks, decision recorded in Sentinel.",
                                     "recipient": {"groupId": "@parameters('TeamsGroupId')", "channelId": "@parameters('TeamsChannelId')"}}}}},
    "Switch_on_decision": {"type": "Switch", "runAfter": {"Post_adaptive_card_and_wait_for_a_response": ["Succeeded"]},
        "expression": "@body('Post_adaptive_card_and_wait_for_a_response')?['data']?['decision']",
        "cases": {
            "Disable": {"case": "disable", "actions": {
                "Disable_service_principal": {"type": "Http", "runAfter": {},
                    "inputs": {"method": "PATCH", "uri": f"{graph}/v1.0/servicePrincipals/@{{variables('SpId')}}",
                               "headers": {"Content-Type": "application/json"}, "body": {"accountEnabled": False}, "authentication": msi}},
                "Comment_disabled": comment("<p>Service principal @{variables('SpId')} disabled by @{body('Post_adaptive_card_and_wait_for_a_response')?['responder']?['userPrincipalName']}. Existing access tokens stay valid until expiry; revoke grants and rotate credentials as follow-up (ISM-2146, ISM-2148).</p>",
                                            {"Disable_service_principal": ["Succeeded"]})}},
            "Benign": {"case": "benign", "actions": {
                "Comment_benign": comment("<p>Marked expected by @{body('Post_adaptive_card_and_wait_for_a_response')?['responder']?['userPrincipalName']}. Add the service principal to the D04 AllowedAppIds list and the AI agent register (ISM-2135).</p>", {})}}},
        "default": {"actions": {
            "Comment_keep": comment("<p>Kept enabled for monitoring by @{body('Post_adaptive_card_and_wait_for_a_response')?['responder']?['userPrincipalName']}. Review permissions at the next ISM-2138 consent review.</p>", {})}}}
}
pb1 = {
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "0.1.0.0",
    "metadata": {"title": "Yuma-PB1-Agent-Permission-Containment", "author": "Yuma IT",
                 "description": "Sentinel incident trigger. Enriches the service principal from Graph, asks the SOC in Teams, and disables the service principal only on human approval.",
                 "comments": "UNVALIDATED skeleton. After deploy: authorise the Teams connection, grant the Logic App managed identity Graph Application.Read.All plus Application.ReadWrite.OwnedBy or Application.ReadWrite.All, and give it Microsoft Sentinel Responder on the workspace."},
    "parameters": {
        "PlaybookName": {"type": "string", "defaultValue": "Yuma-PB1-Agent-Permission-Containment"},
        "TeamsGroupId": {"type": "string", "metadata": {"description": "Team (group) ID for the SOC channel"}},
        "TeamsChannelId": {"type": "string", "metadata": {"description": "SOC channel ID"}}
    },
    "variables": {"SentinelConnectionName": "[concat('azuresentinel-', parameters('PlaybookName'))]",
                  "TeamsConnectionName": "[concat('teams-', parameters('PlaybookName'))]"},
    "resources": [
        {"type": "Microsoft.Web/connections", "apiVersion": "2016-06-01", "name": "[variables('SentinelConnectionName')]",
         "location": "[resourceGroup().location]", "kind": "V1",
         "properties": {"displayName": "[variables('SentinelConnectionName')]", "customParameterValues": {}, "parameterValueType": "Alternative",
                        "api": {"id": "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.Web/locations/', resourceGroup().location, '/managedApis/azuresentinel')]"}}},
        {"type": "Microsoft.Web/connections", "apiVersion": "2016-06-01", "name": "[variables('TeamsConnectionName')]",
         "location": "[resourceGroup().location]",
         "properties": {"displayName": "[variables('TeamsConnectionName')]", "customParameterValues": {},
                        "api": {"id": "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.Web/locations/', resourceGroup().location, '/managedApis/teams')]"}}},
        {"type": "Microsoft.Logic/workflows", "apiVersion": "2017-07-01", "name": "[parameters('PlaybookName')]",
         "location": "[resourceGroup().location]", "identity": {"type": "SystemAssigned"},
         "tags": {"hidden-SentinelTemplateName": "Yuma-PB1-Agent-Permission-Containment", "hidden-SentinelTemplateVersion": "0.1"},
         "dependsOn": ["[resourceId('Microsoft.Web/connections', variables('SentinelConnectionName'))]",
                       "[resourceId('Microsoft.Web/connections', variables('TeamsConnectionName'))]"],
         "properties": {
             "state": "Disabled",
             "definition": {
                 "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
                 "contentVersion": "1.0.0.0",
                 "parameters": {"$connections": {"type": "Object", "defaultValue": {}},
                                "TeamsGroupId": {"type": "String", "defaultValue": "[parameters('TeamsGroupId')]"},
                                "TeamsChannelId": {"type": "String", "defaultValue": "[parameters('TeamsChannelId')]"}},
                 "triggers": {"Microsoft_Sentinel_incident": {"type": "ApiConnectionWebhook",
                     "inputs": {"host": sentinel_conn, "path": "/incident-creation", "body": {"callback_url": "@{listCallbackUrl()}"}}}},
                 "actions": actions,
                 "outputs": {}
             },
             "parameters": {"$connections": {"value": {
                 "azuresentinel": {"connectionId": "[resourceId('Microsoft.Web/connections', variables('SentinelConnectionName'))]",
                                   "connectionName": "[variables('SentinelConnectionName')]",
                                   "id": "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.Web/locations/', resourceGroup().location, '/managedApis/azuresentinel')]",
                                   "connectionProperties": {"authentication": {"type": "ManagedServiceIdentity"}}},
                 "teams": {"connectionId": "[resourceId('Microsoft.Web/connections', variables('TeamsConnectionName'))]",
                           "connectionName": "[variables('TeamsConnectionName')]",
                           "id": "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.Web/locations/', resourceGroup().location, '/managedApis/teams')]"}}}}
         }}
    ],
    "outputs": {"playbookPrincipalId": {"type": "string", "value": "[reference(resourceId('Microsoft.Logic/workflows', parameters('PlaybookName')), '2017-07-01', 'full').identity.principalId]"}}
}

auto = {
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "0.1.0.0",
    "metadata": {"comments": "UNVALIDATED. Runs PB1 on incidents created by the D04 rule. Sentinel needs Microsoft Sentinel Automation Contributor on the playbook resource group."},
    "parameters": {
        "workspace": {"type": "string"},
        "automationRuleId": {"type": "string", "defaultValue": "[newGuid()]"},
        "analyticsRuleResourceId": {"type": "string", "metadata": {"description": "ruleResourceId output from analytics-rule-D04.json"}},
        "playbookResourceId": {"type": "string", "metadata": {"description": "Resource ID of Yuma-PB1-Agent-Permission-Containment"}}
    },
    "resources": [{
        "type": "Microsoft.OperationalInsights/workspaces/providers/automationRules",
        "apiVersion": "2023-02-01",
        "name": "[concat(parameters('workspace'), '/Microsoft.SecurityInsights/', parameters('automationRuleId'))]",
        "properties": {
            "displayName": "Yuma: run PB1 on AI agent permission incidents",
            "order": 10,
            "triggeringLogic": {"isEnabled": True, "triggersOn": "Incidents", "triggersWhen": "Created",
                "conditions": [{"conditionType": "Property", "conditionProperties": {
                    "propertyName": "IncidentRelatedAnalyticRuleIds", "operator": "Contains",
                    "propertyValues": ["[parameters('analyticsRuleResourceId')]"]}}]},
            "actions": [{"order": 1, "actionType": "RunPlaybook",
                         "actionConfiguration": {"logicAppResourceId": "[parameters('playbookResourceId')]", "tenantId": "[subscription().tenantId]"}}]
        }
    }]
}

# ---------------- shared Logic App wrapper for recurrence playbooks ----------------
def recurrence_playbook(title, description, comments, params, wf_params, recurrence, wf_actions):
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "0.1.0.0",
        "metadata": {"title": title, "author": "Yuma IT", "description": description, "comments": comments},
        "parameters": {"PlaybookName": {"type": "string", "defaultValue": title}, **params},
        "resources": [{
            "type": "Microsoft.Logic/workflows", "apiVersion": "2017-07-01", "name": "[parameters('PlaybookName')]",
            "location": "[resourceGroup().location]", "identity": {"type": "SystemAssigned"},
            "tags": {"hidden-SentinelTemplateName": title, "hidden-SentinelTemplateVersion": "0.1"},
            "properties": {
                "state": "Disabled",
                "definition": {
                    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
                    "contentVersion": "1.0.0.0",
                    "parameters": wf_params,
                    "triggers": {"Recurrence": {"type": "Recurrence", "recurrence": recurrence}},
                    "actions": wf_actions,
                    "outputs": {}
                }
            }
        }],
        "outputs": {"playbookPrincipalId": {"type": "string", "value": "[reference(resourceId('Microsoft.Logic/workflows', parameters('PlaybookName')), '2017-07-01', 'full').identity.principalId]"}}
    }

# ---------------- PB4 register sync (AgentsInfo -> AIAgentRegister_CL) ----------------
pb4_query = "\n".join(l for l in (root / "functions/PB4-AgentsInfoRegisterSync.kql").read_text().splitlines() if not l.startswith("//")).strip()
monitor_msi = {"type": "ManagedServiceIdentity", "audience": "https://monitor.azure.com"}
pb4_actions = {
    "Run_hunting_query": {"type": "Http", "runAfter": {},
        "inputs": {"method": "POST", "uri": f"{graph}/v1.0/security/runHuntingQuery",
                   "headers": {"Content-Type": "application/json"}, "body": {"Query": pb4_query}, "authentication": msi}},
    "Select_register_rows": {"type": "Select", "runAfter": {"Run_hunting_query": ["Succeeded"]},
        "inputs": {"from": "@coalesce(body('Run_hunting_query')?['results'], json('[]'))", "select": {
            "TimeGenerated": "@utcNow()",
            "RecordType": "@if(equals(item()?['LifecycleStatus'], 'Deleted'), 'Retired', 'RegisterSnapshot')",
            "AgentKey": "@item()?['AgentId']",
            "AgentName": "@item()?['AgentName']",
            "Source": "AgentsInfo",
            "Platform": "@item()?['Platform']",
            "EntraAgentId": "@item()?['EntraAgentId']",
            "EntraBlueprintId": "@item()?['EntraBlueprintId']",
            "Owners": "@item()?['Owners']",
            "BusinessPurpose": "@item()?['AgentDescription']",
            "Identities": "@createArray(item()?['EntraAgentId'], item()?['EntraBlueprintId'])",
            "Permissions": "@item()?['Permissions']",
            "DeclaredTools": "@item()?['DeclaredTools']",
            "McpServers": "@item()?['McpServers']",
            "DataSources": "@item()?['DeclaredDataSources']",
            "SharedWith": "@item()?['SharedWith']",
            "LifecycleStatus": "@item()?['LifecycleStatus']",
            "Notes": "@concat('ToolsAuthenticationType=', string(item()?['ToolsAuthenticationType']), '; PublishedStatus=', string(item()?['PublishedStatus']))"}}},
    "For_each_batch": {"type": "Foreach", "runAfter": {"Select_register_rows": ["Succeeded"]},
        "foreach": "@chunk(body('Select_register_rows'), 200)",
        "runtimeConfiguration": {"concurrency": {"repetitions": 1}},
        "actions": {"Send_to_register": {"type": "Http", "runAfter": {},
            "inputs": {"method": "POST",
                       "uri": "@{parameters('LogsIngestionEndpoint')}/dataCollectionRules/@{parameters('DcrImmutableId')}/streams/Custom-AIAgentRegister?api-version=2023-01-01",
                       "headers": {"Content-Type": "application/json"}, "body": "@items('For_each_batch')",
                       "authentication": monitor_msi}}}}
}
pb4 = recurrence_playbook(
    "Yuma-PB4-AI-Agent-Register-Sync",
    "Daily: reads AgentsInfo through Microsoft Graph runHuntingQuery and writes register snapshots (or Retired records) to AIAgentRegister_CL through the Logs Ingestion API.",
    "UNVALIDATED skeleton. Grant the managed identity Graph ThreatHunting.Read.All (application) and Monitoring Metrics Publisher on the DCR. LogsIngestionEndpoint and DcrImmutableId come from the register-infra.json outputs.",
    {"LogsIngestionEndpoint": {"type": "string", "metadata": {"description": "register-infra output logsIngestionEndpoint"}},
     "DcrImmutableId": {"type": "string", "metadata": {"description": "register-infra output dcrImmutableId"}}},
    {"LogsIngestionEndpoint": {"type": "String", "defaultValue": "[parameters('LogsIngestionEndpoint')]"},
     "DcrImmutableId": {"type": "String", "defaultValue": "[parameters('DcrImmutableId')]"}},
    {"frequency": "Day", "interval": 1},
    pb4_actions)

# ---------------- PB5 ISM evidence export (functions -> dated files in Blob storage) ----------------
la_msi = {"type": "ManagedServiceIdentity", "audience": "https://api.loganalytics.io"}
storage_msi = {"type": "ManagedServiceIdentity", "audience": "https://storage.azure.com/"}
def la_query(fn, after):
    return {"type": "Http", "runAfter": after,
            "inputs": {"method": "POST", "uri": "https://api.loganalytics.azure.com/v1/workspaces/@{parameters('WorkspaceId')}/query",
                       "headers": {"Content-Type": "application/json"}, "body": {"query": f"{fn}()"}, "authentication": la_msi}}
def put_blob(filename, content_type, body, after):
    return {"type": "Http", "runAfter": after,
            "inputs": {"method": "PUT",
                       "uri": "https://@{parameters('StorageAccountName')}.blob.core.windows.net/@{parameters('ContainerName')}/@{variables('RunFolder')}/" + filename,
                       "headers": {"x-ms-blob-type": "BlockBlob", "x-ms-version": "2021-08-06", "x-ms-date": "@{utcNow('R')}",
                                   "Content-Type": content_type},
                       "body": body, "authentication": storage_msi}}
pb5_actions = {
    "Init_RunFolder": {"type": "InitializeVariable", "runAfter": {},
        "inputs": {"variables": [{"name": "RunFolder", "type": "string", "value": "@{formatDateTime(utcNow(), 'yyyy-MM-dd')}"}]}},
    "Query_register_csv": la_query("YumaEvidenceRegisterCsv", {"Init_RunFolder": ["Succeeded"]}),
    "Query_controls_csv": la_query("YumaEvidenceControlsCsv", {"Init_RunFolder": ["Succeeded"]}),
    "Query_summary_md": la_query("YumaEvidenceMarkdown", {"Init_RunFolder": ["Succeeded"]}),
    "Put_agent_register_csv": put_blob("agent-register.csv", "text/csv; charset=utf-8",
        "@{body('Query_register_csv')?['tables'][0]?['rows'][0][0]}", {"Query_register_csv": ["Succeeded"]}),
    "Put_ism_controls_csv": put_blob("ism-controls.csv", "text/csv; charset=utf-8",
        "@{body('Query_controls_csv')?['tables'][0]?['rows'][0][0]}", {"Query_controls_csv": ["Succeeded"]}),
    "Put_summary_md": put_blob("summary.md", "text/markdown; charset=utf-8",
        "@{body('Query_summary_md')?['tables'][0]?['rows'][0][0]}", {"Query_summary_md": ["Succeeded"]}),
    "Put_manifest_json": put_blob("manifest.json", "application/json",
        {"generatedUtc": "@{utcNow()}", "workspaceId": "@{parameters('WorkspaceId')}", "logicAppRunId": "@{workflow()?['run']?['name']}",
         "files": ["agent-register.csv", "ism-controls.csv", "summary.md"],
         "sourceFunctions": ["YumaEvidenceRegisterCsv", "YumaEvidenceControlsCsv", "YumaEvidenceMarkdown"],
         "note": "Evidence to support an assessment, not a compliance determination."},
        {"Put_agent_register_csv": ["Succeeded"], "Put_ism_controls_csv": ["Succeeded"], "Put_summary_md": ["Succeeded"]})
}
pb5 = recurrence_playbook(
    "Yuma-PB5-ISM-Evidence-Export",
    "Monthly (or run on demand): calls the pack's evidence functions and writes a dated folder (agent-register.csv, ism-controls.csv, summary.md, manifest.json) to a Blob container for assessors.",
    "UNVALIDATED skeleton. Grant the managed identity Log Analytics Reader on the workspace and Storage Blob Data Contributor on the container. Turn on blob versioning or a time-based immutability policy on the container so evidence cannot be altered.",
    {"WorkspaceId": {"type": "string", "metadata": {"description": "Log Analytics workspace ID (GUID)"}},
     "StorageAccountName": {"type": "string"},
     "ContainerName": {"type": "string", "defaultValue": "ism-evidence"}},
    {"WorkspaceId": {"type": "String", "defaultValue": "[parameters('WorkspaceId')]"},
     "StorageAccountName": {"type": "String", "defaultValue": "[parameters('StorageAccountName')]"},
     "ContainerName": {"type": "String", "defaultValue": "[parameters('ContainerName')]"}},
    {"frequency": "Month", "interval": 1, "schedule": {"monthDays": [1], "hours": ["7"]}, "timeZone": "AUS Eastern Standard Time"},
    pb5_actions)

for name, obj in [("analytics-rule-D04.json", d04), ("analytics-rule-D14.json", d14),
                  ("playbook-PB1-agent-containment.json", pb1), ("automation-rule-D04-PB1.json", auto),
                  ("playbook-PB4-register-sync.json", pb4), ("playbook-PB5-ism-evidence-export.json", pb5)]:
    (out / name).write_text(json.dumps(obj, indent=2) + "\n")
    print("wrote", name)

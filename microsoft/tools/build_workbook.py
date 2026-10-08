#!/usr/bin/env python3
"""Build the Sentinel workbook 'Yuma AI Agent Register and ISM Evidence'.
Writes deploy/workbook/yuma-ai-agent-register.workbook.json (gallery JSON, Notebook/1.0) and every query to
deploy/workbook/queries/*.kql (with {TimeRange} replaced by '> ago(30d)') so tools/kqlcheck.js can bind them.
The placeholder __WORKSPACE_RESOURCE_ID__ is replaced at deploy time by deploy/bicep/workbook.bicep."""
import json, pathlib, uuid
root = pathlib.Path(__file__).resolve().parent.parent
wbdir = root / "deploy/workbook"
qdir = wbdir / "queries"
WS = "microsoft.operationalinsights/workspaces"

Q = {}
Q["overview_tiles"] = """let Reg = YumaAIRegister();
union
    (Reg | summarize Value = count() | extend Label = "Active agents and AI apps", Ord = 1),
    (Reg | where GapCount > 0 | summarize Value = count() | extend Label = "Missing ISM-2135 fields", Ord = 2),
    (Reg | where ReviewStatus in ("Overdue", "Never reviewed") | summarize Value = count() | extend Label = "Review overdue (ISM-2138)", Ord = 3),
    (Reg | where Flag_HighRiskPermissions | summarize Value = count() | extend Label = "High-risk permissions (ISM-2156)", Ord = 4),
    (Reg | where Flag_HasMcp | summarize Value = count() | extend Label = "Agents using MCP servers", Ord = 5)
| order by Ord asc
| project Label, Value"""
Q["overview_status_pie"] = """YumaISMControlStatus()
| summarize Controls = count() by Status"""
Q["overview_status_table"] = """YumaISMControlStatus()
| project ControlId, Theme, Status, Metric"""
Q["register_table"] = """YumaAIRegister()
| project AgentName, Source, Platform, Owners, BusinessPurpose, EntraAgentId, ServicePrincipalId, AppId,
          HighRiskPermissions, McpServers, Decision, ReviewStatus, NextReviewDue, GapCount, Gap_NoOwner, Gap_NoPurpose,
          Gap_NoUniqueIdentity, Gap_NoPermissionsRecorded, LastSnapshotAt
| order by GapCount desc, AgentName asc"""
Q["register_gaps_bar"] = """let Reg = YumaAIRegister();
union
    (Reg | where Gap_NoOwner | summarize Agents = count() | extend Gap = "No owner (ISM-2135)"),
    (Reg | where Gap_NoPurpose | summarize Agents = count() | extend Gap = "No business purpose (ISM-2135)"),
    (Reg | where Gap_NoUniqueIdentity | summarize Agents = count() | extend Gap = "No unique identity (ISM-2133)"),
    (Reg | where Gap_NoPermissionsRecorded | summarize Agents = count() | extend Gap = "No permissions recorded (ISM-2135)"),
    (Reg | where Flag_HighRiskPermissions | summarize Agents = count() | extend Gap = "High-risk permissions (ISM-2156)")
| project Gap, Agents"""
Q["ism_table"] = """YumaISMControlStatus()
| project ControlId, Theme, Status, Metric, AlertsLookback, PackEvidence, EvidenceMethod, Control, CheckedAtUtc"""
Q["consent_timechart"] = """AuditLogs
| where TimeGenerated {TimeRange}
| where OperationName =~ "Consent to application" and Result =~ "success"
| mv-apply TargetResource = TargetResources on (
      where tostring(TargetResource.type) =~ "ServicePrincipal" | extend Props = TargetResource.modifiedProperties | take 1)
| mv-apply Prop = Props on (
      where tostring(Prop.displayName) == "ConsentContext.IsAdminConsent" | extend IsAdmin = tostring(Prop.newValue) has "True")
| extend ConsentKind = iff(IsAdmin, "Admin consent", "User consent (ISM-2137 gap)")
| summarize Consents = count() by bin(TimeGenerated, 1d), ConsentKind"""
Q["consent_events_table"] = """AuditLogs
| where TimeGenerated {TimeRange}
| where OperationName =~ "Consent to application" and Result =~ "success"
| mv-apply TargetResource = TargetResources on (
      where tostring(TargetResource.type) =~ "ServicePrincipal"
      | extend AppName = tostring(TargetResource.displayName), AppSpId = tostring(TargetResource.id),
               AgentType = tostring(TargetResource.agentType), Props = TargetResource.modifiedProperties
      | take 1)
| mv-apply Prop = Props on (
      summarize Bag = make_bag(bag_pack(tostring(Prop.displayName), trim(@'[\\"\\s]+', tostring(Prop.newValue))), 100))
| extend IsAdminConsent = tostring(Bag["ConsentContext.IsAdminConsent"]), Permissions = tostring(Bag["ConsentAction.Permissions"])
| extend ConsentedBy = tostring(InitiatedBy.user.userPrincipalName)
| join kind=leftouter (YumaAIRegister() | project AppSpId = ServicePrincipalId, InRegister = true, RegisterDecision = Decision) on AppSpId
| project TimeGenerated, AppName, AppSpId, AgentType, IsAdminConsent, ConsentedBy, Permissions,
          InRegister = coalesce(InRegister, false), RegisterDecision
| order by TimeGenerated desc"""
Q["consent_decisions_table"] = """AIAgentRegister_CL
| where TimeGenerated {TimeRange}
| where RecordType == "ConsentDecision"
| project TimeGenerated, AgentName, Decision, DecisionBy, DecisionReason, ConsentType, IsAdminConsent, ConsentedBy,
          Permissions, IncidentArmId
| order by TimeGenerated desc"""
Q["review_bar"] = """YumaAIRegister()
| summarize Agents = count() by ReviewStatus"""
Q["review_due_table"] = """YumaAIRegister()
| where ReviewStatus != "Current"
| project AgentName, Owners, Decision, LastReview, NextReviewDue, ReviewStatus, HighRiskPermissions
| order by NextReviewDue asc"""
Q["review_history_table"] = """AIAgentRegister_CL
| where TimeGenerated {TimeRange}
| where RecordType in ("ReviewCompleted", "Retired")
| project TimeGenerated, RecordType, AgentName, Decision, DecisionBy, DecisionReason, Notes
| order by TimeGenerated desc"""
Q["detections_timechart"] = """SecurityAlert
| where TimeGenerated {TimeRange}
| where AlertName startswith "Yuma AIA-"
| extend DetectionId = extract(@"Yuma AIA-(D\\d+)", 1, AlertName)
| summarize Alerts = count() by bin(TimeGenerated, 1d), DetectionId"""
Q["detections_table"] = """SecurityAlert
| where TimeGenerated {TimeRange}
| where AlertName startswith "Yuma AIA-"
| extend DetectionId = extract(@"Yuma AIA-(D\\d+)", 1, AlertName)
| project TimeGenerated, DetectionId, AlertName, AlertSeverity, CompromisedEntity, SystemAlertId
| order by TimeGenerated desc"""

def gid(name):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "yuma-ai-pack/" + name))

def vis(tab):
    return {"parameterName": "Tab", "comparison": "isEqualTo", "value": tab}

status_fmt = {"columnMatch": "Status", "formatter": 18, "formatOptions": {"thresholdsOptions": "icons", "thresholdsGrid": [
    {"operator": "==", "thresholdValue": "Evidence present", "representation": "success", "text": "{0}"},
    {"operator": "==", "thresholdValue": "Gap", "representation": "2", "text": "{0}"},
    {"operator": "==", "thresholdValue": "No data", "representation": "unknown", "text": "{0}"},
    {"operator": "Default", "thresholdValue": None, "representation": "info", "text": "{0}"}]}}
review_fmt = {"columnMatch": "ReviewStatus", "formatter": 18, "formatOptions": {"thresholdsOptions": "icons", "thresholdsGrid": [
    {"operator": "==", "thresholdValue": "Current", "representation": "success", "text": "{0}"},
    {"operator": "==", "thresholdValue": "Due within 30 days", "representation": "warning", "text": "{0}"},
    {"operator": "Default", "thresholdValue": None, "representation": "2", "text": "{0}"}]}}

def query_item(name, title, vis_type, tab, width=None, extra=None):
    content = {"version": "KqlItem/1.0", "query": Q[name], "size": 0, "title": title,
               "queryType": 0, "resourceType": WS, "visualization": vis_type}
    if "{TimeRange}" in Q[name]:
        content["timeContextFromParameter"] = "TimeRange"
    if extra:
        content.update(extra)
    item = {"type": 3, "content": content, "conditionalVisibility": vis(tab), "name": name}
    if width:
        item["customWidth"] = str(width)
    return item

def text_item(name, md, tab=None):
    item = {"type": 1, "content": {"json": md}, "name": name}
    if tab:
        item["conditionalVisibility"] = vis(tab)
    return item

tabs = [("overview", "Overview"), ("register", "Agent register"), ("ism", "ISM coverage"),
        ("consent", "Consent history"), ("review", "Review status"), ("detections", "Detections")]
items = [
    text_item("header", "## Yuma AI Agent Register and ISM Evidence\n"
              "Agent register (ISM-2134, ISM-2135), ISM-2133 to 2140 and ISM-2156 to 2159 evidence status, consent "
              "history and six-monthly review status. Data comes from `AIAgentRegister_CL`, the `YumaAIRegister()` and "
              "`YumaISMControlStatus()` functions, Entra logs and Yuma analytics rules. Statuses are evidence to support "
              "an assessment, not a compliance determination."),
    {"type": 9, "name": "parameters", "content": {"version": "KqlParameterItem/1.0", "style": "pills", "queryType": 0,
        "resourceType": WS, "parameters": [{"id": gid("TimeRange"), "version": "KqlParameterItem/1.0", "name": "TimeRange",
            "label": "Time range", "type": 4, "isRequired": True, "value": {"durationMs": 2592000000},
            "typeSettings": {"selectableValues": [{"durationMs": 604800000}, {"durationMs": 2592000000},
                                                  {"durationMs": 7776000000}, {"durationMs": 15552000000}]}}]}},
    {"type": 11, "name": "tabs", "content": {"version": "LinkItem/1.0", "style": "tabs", "links": [
        {"id": gid("tab-" + t), "cellValue": "Tab", "linkTarget": "parameter", "linkLabel": label, "subTarget": t,
         "style": "link"} for t, label in tabs]}},
    query_item("overview_tiles", "Register at a glance", "tiles", "overview", extra={"tileSettings": {
        "titleContent": {"columnMatch": "Label"}, "leftContent": {"columnMatch": "Value", "formatter": 12},
        "showBorder": True}}),
    query_item("overview_status_pie", "ISM control evidence status", "piechart", "overview", width=40),
    query_item("overview_status_table", "Controls", "table", "overview", width=60,
               extra={"gridSettings": {"formatters": [status_fmt]}}),
    query_item("register_table", "AI agent register (ISM-2135 fields and gaps)", "table", "register",
               extra={"gridSettings": {"formatters": [review_fmt], "filter": True}}),
    query_item("register_gaps_bar", "Register gaps", "barchart", "register"),
    text_item("ism_note", "Status meanings: **Evidence present** means the data shows the expected state. **Gap** means the "
              "data shows a problem. **No data** means the source is not connected. **Attestation required** means the "
              "metric needs a written statement from the control owner.", "ism"),
    query_item("ism_table", "ISM-2133 to 2140 and ISM-2156 to 2159", "table", "ism",
               extra={"gridSettings": {"formatters": [status_fmt], "filter": True}}),
    query_item("consent_timechart", "App consents per day", "timechart", "consent"),
    query_item("consent_events_table", "Consent events (Entra audit) and register match", "table", "consent",
               extra={"gridSettings": {"filter": True}}),
    query_item("consent_decisions_table", "Consent decisions recorded by PB2", "table", "consent"),
    query_item("review_bar", "Review status (six-monthly, ISM-2138)", "barchart", "review", width=40),
    query_item("review_due_table", "Reviews due or overdue", "table", "review", width=60,
               extra={"gridSettings": {"formatters": [review_fmt]}}),
    query_item("review_history_table", "Completed reviews and retirements", "table", "review"),
    query_item("detections_timechart", "Yuma AI detections", "timechart", "detections"),
    query_item("detections_table", "Recent Yuma AI alerts", "table", "detections"),
]
wb = {"version": "Notebook/1.0", "items": items, "fallbackResourceIds": ["__WORKSPACE_RESOURCE_ID__"],
      "fromTemplateId": "yuma-ai-agent-register",
      "$schema": "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json"}
(wbdir / "yuma-ai-agent-register.workbook.json").write_text(json.dumps(wb, indent=2) + "\n")
for old in qdir.glob("*.kql"):
    old.unlink()
for name, q in Q.items():
    (qdir / f"{name}.kql").write_text(q.replace("{TimeRange}", "> ago(30d)") + "\n")
print("workbook items:", len(items), "queries:", len(Q))

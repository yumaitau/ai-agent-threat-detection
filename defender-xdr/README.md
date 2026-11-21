# Microsoft Defender XDR custom detection rules

This folder packages the Yuma AI agent detections that run natively on Microsoft Defender XDR Advanced Hunting tables. All rules ship in the **disabled** state so you can review query output and tune thresholds in your tenant before enabling alerts.

## Included rules and queries

| ID | Type | Tables | Frequency | Severity | Entity mapping | Files |
|---|---|---|---|---|---|---|
| **D01** | Custom detection rule | `DeviceNetworkEvents` | Every 3 hours (`PT3H`) | Medium | Device (`DeviceId`), Account (`InitiatingProcessAccountObjectId`, `InitiatingProcessAccountUpn`), File (`InitiatingProcessSHA256`), IP (`RemoteIP`) | [Rule JSON](rules/D01-ShadowAI-NonBrowserProcessToAIAPI.json), [KQL](queries/D01-ShadowAI-NonBrowserProcessToAIAPI.kql) |
| **D10** | Custom detection rule | `AlertInfo`, `AlertEvidence`, `CloudAppEvents` | Every 1 hour (`PT1H`) | High | Account (`AccountObjectId`, `AccountUpn`) | [Rule JSON](rules/D10-PromptInjectionThenExfiltration.json), [KQL](queries/D10-PromptInjectionThenExfiltration.kql) |
| **D09** | Advanced Hunting inventory query | `AgentsInfo` | Manual or scheduled via PB4 | Informational | Agent inventory (no `ReportId` column) | [KQL](queries/D09-AgentRegisterReview-AgentsInfo.kql) |

### Why other Microsoft detections stay in Sentinel

Detections D04, D05, D06, D07, D08, D13, D14 and D15 depend on Log Analytics tables (`AuditLogs`, `AADServicePrincipalSignInLogs`, `MicrosoftGraphActivityLogs`, `AGWFirewallLogs`, `AGWAccessLogs`, `NetworkAccessTraffic`) or Sentinel watchlists (`YumaAIRegisterApproved`). Deploy those through the [Microsoft Sentinel Content Hub solution](../Solutions/YumaAIAgentThreatDetection/Data/Solution_YumaAIAgentThreatDetection.json) or the one-click [ARM template](../microsoft/deploy/azuredeploy.json). Note that the Sentinel version of D10 also correlates `CopilotActivity` in addition to Defender XDR alerts.

## How to import into Microsoft Defender XDR

### Option 1: Microsoft Defender portal (UI)

1. Sign in to the Microsoft Defender portal (`https://security.microsoft.com`) with **Security Administrator** or Unified RBAC **Detection tuning (Manage)** permissions.
2. Go to **Investigation & response** > **Hunting** > **Advanced hunting**.
3. Open one of the KQL files under `defender-xdr/queries/` (for example [D01-ShadowAI-NonBrowserProcessToAIAPI.kql](queries/D01-ShadowAI-NonBrowserProcessToAIAPI.kql)), paste it into the query editor and run it to inspect baseline hits and tune allow-lists (such as `ApprovedProcesses` in D01 or `MinExfilEvents` in D10).
4. Select **Create detection rule** and enter the settings from the corresponding JSON file in `defender-xdr/rules/`:
   - **Detection name**: `displayName`
   - **Frequency**: `schedule.frequency` (`Every 3 hours` for D01, `Every hour` for D10)
   - **Alert title, severity, category, description and recommended actions**: from `detectionAction.alertTemplate`
   - **MITRE ATT&CK techniques**: from `detectionAction.alertTemplate.tactics`
   - **Impacted entities**: map the columns listed in `detectionAction.alertTemplate.entityMappings` (`DeviceId`, `InitiatingProcessAccountObjectId` / `AccountObjectId`, `InitiatingProcessSHA256`, `RemoteIP`)
5. Leave automated response actions off until you have reviewed initial alerts, then save the rule.

### Option 2: Microsoft Graph Security API

The JSON files under `defender-xdr/rules/` follow the `microsoft.graph.security.detectionRule` payload structure for `POST https://graph.microsoft.com/beta/security/rules/detectionRules` (requires `CustomDetection.ReadWrite.All` plus appropriate Defender XDR RBAC).

Example using the Microsoft Graph PowerShell SDK:

```powershell
Connect-MgGraph -Scopes "CustomDetection.ReadWrite.All"

foreach ($rule in Get-ChildItem -Path "defender-xdr/rules" -Filter "*.json") {
    $body = Get-Content -Path $rule.FullName -Raw
    Invoke-MgGraphRequest `
        -Method POST `
        -Uri "https://graph.microsoft.com/beta/security/rules/detectionRules" `
        -ContentType "application/json" `
        -Body $body
}
```

Every rule in `defender-xdr/rules/` sets `"status": "disabled"`. After importing, run the rule manually or review hits in Advanced Hunting, adjust thresholds for your environment, and enable the rule in the Defender portal.

## Validation status

All KQL queries in this folder are parsed and semantically bound offline against bundled Microsoft Learn schemas (`microsoft/tools/schemas.json`), and each JSON rule definition is verified for required Defender XDR columns (`Timestamp`, `ReportId`), schedule frequency, severity and entity mappings. They have **not** been tested against a live Defender XDR tenant.

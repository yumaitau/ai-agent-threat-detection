# Microsoft Sentinel and Defender XDR

Detections, response playbooks and an AI agent register for Microsoft Sentinel and Defender XDR.

**Validation status:** the implementation passes the offline checks listed in [validation](../docs/validation.md). It has **NOT been tested against live tenants or accounts**. Tune thresholds against representative data before enabling alerts or response actions. Some entries are draft hunts or specifications.

See the [combined detection catalogue](../mappings/README.md) for all 15 entries on this platform and their original framework mappings.

## SOAR playbooks

| PB | Trigger | Flow | Deliverable |
|---|---|---|---|
| **PB1 Agent Permission Containment** | D04, D07, D08 | Graph enrichment (SP, owners, assignments) → incident comment → Teams adaptive card → on approval `PATCH servicePrincipal accountEnabled=false` → comment | **ARM skeleton** `deploy/playbook-PB1-agent-containment.json` + automation rule `deploy/automation-rule-D04-PB1.json` |
| **PB2 AI App Consent → Register** | D05 | Enrich → write a RegisterSnapshot to `AIAgentRegister_CL` (Logs Ingestion API) → owner approval → write a ConsentDecision → approve: add to the `YumaAIRegisterApproved` watchlist; revoke: delete the grant → 6-monthly review job (ISM-2138) | Design `playbooks/PB2-...md` |
| **PB3 Agentic Scrape / Exploit Block** | D14, D13 | IP entities → allow-list → GreyNoise, AbuseIPDB, ThreatFox → score → (approval or pre-approved auto) block in an App Gateway WAF custom rule or a Defender indicator, with expiry → comment | Design `playbooks/PB3-...md` |
| **PB4 AI Agent Register Sync** | Daily | Graph `runHuntingQuery` on AgentsInfo → map to the register schema → batched Logs Ingestion API POST (Retired records for deleted agents) | **ARM skeleton** `deploy/playbook-PB4-register-sync.json` |
| **PB5 ISM Evidence Export** | Monthly + on demand | Logs query API calls the three evidence functions → dated folder in Blob (`agent-register.csv`, `ism-controls.csv`, `summary.md`, `manifest.json`); SharePoint option | **ARM skeleton** `deploy/playbook-PB5-ism-evidence-export.json` |

Every destructive step sits behind a human decision unless you pre-approves auto-block (PB3 only).

The permissions each playbook needs are themselves high-risk, for example Application.ReadWrite.All or AgentIdentity.ReadWrite.All to disable a service principal (https://learn.microsoft.com/en-us/graph/api/serviceprincipal-update). The designs say how to contain that.


## AI agent register and ISM evidence (all inside Sentinel)

| Piece | What it is | File |
|---|---|---|
| Register table `AIAgentRegister_CL` | Custom Log Analytics table, append-only history. RecordType values: RegisterSnapshot, ConsentDecision, ReviewCompleted, Retired. Columns cover the ISM-2135 fields (identifier, owner, purpose, identities, permissions, tools, MCP servers, data sources) plus decision, reviewer and review dates. Retention defaults to 365 days interactive and 2,555 days total; set to your records policy | `deploy/register/AIAgentRegister_CL.columns.json` |
| DCR (direct ingestion) | Stream `Custom-AIAgentRegister` → `Custom-AIAgentRegister_CL`. Writers: PB2, PB4, or a manual script. Callers need Monitoring Metrics Publisher on the DCR | `deploy/bicep/register-infra.bicep` |
| Watchlist `YumaAIRegisterApproved` | Approved service principals. D04 and D05 suppress these. PB2 maintains it | `deploy/register/watchlist-YumaAIRegisterApproved.csv` |
| Watchlist `YumaISMControlMap` | ISM-2133 to 2140 and ISM-2156 to 2159: control text (ASD ISM, September 2026), theme, pack evidence, evidence method | `deploy/register/watchlist-YumaISMControlMap.csv` |
| Function `YumaAIRegister()` | Current register, one row per agent. Includes ISM-2135 field gaps, the ISM-2133 identity gap, high-risk permissions and ISM-2138 review status (Never reviewed / Overdue / Due within 30 days / Current) | `functions/YumaAIRegister.kql` |
| Function `YumaISMControlStatus()` | One row per control, with status (Evidence present / Gap / No data / Attestation required) and a metric computed from the register, AuditLogs, sign-in logs, Graph activity, GSA and Copilot logs, and Yuma alerts | `functions/YumaISMControlStatus.kql` |
| Functions `YumaEvidenceRegisterCsv()`, `YumaEvidenceControlsCsv()`, `YumaEvidenceMarkdown()` | Single-cell CSV and markdown outputs used by PB5 | `functions/` |
| Workbook "Yuma AI Agent Register and ISM Evidence" | Six tabs: Overview, Agent register, ISM coverage, Consent history (Entra audit + PB2 decisions), Review status, Detections | `deploy/workbook/`, `deploy/workbook.json` |
| PB5 evidence export | A dated folder in a customer-owned Blob container (immutability policy recommended), or SharePoint | `deploy/playbook-PB5-ism-evidence-export.json` |

**How data reaches the register:**
- PB4 syncs AgentsInfo daily, covering Copilot Studio, Foundry and the other platforms Defender inventories.
- PB2 adds consented Entra AI apps and every human decision.
- Anything else can be posted to the same DCR stream.

The register is an evidence source to support an assessment. It isn't a compliance determination: "Attestation required" controls still need a written statement from the control owner.


## Licence and data prerequisites

| Table | What you needs | Source |
|---|---|---|
| AuditLogs | Entra ID (any tier) + Sentinel Entra ID connector | https://learn.microsoft.com/en-us/azure/sentinel/connect-azure-active-directory |
| AADServicePrincipalSignInLogs | **Entra ID P1 or P2** to ingest sign-in logs | same |
| MicrosoftGraphActivityLogs | **Entra ID P1 or P2** + diagnostic setting; high volume, so cost-check | https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview |
| CloudAppEvents | Defender for Cloud Apps with the Microsoft 365 app connector | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table |
| AlertInfo, AlertEvidence, DeviceNetworkEvents, DeviceProcessEvents | Defender XDR; Device* tables need Defender for Endpoint | https://learn.microsoft.com/en-us/defender-xdr/prerequisites |
| AgentsInfo (preview) | Defender XDR or Defender for Cloud Apps; Learn points Agent 365 customers to it. Replaces AIAgentsInfo, which was only accessible until 1 Jul 2026 | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-agentsinfo-table |
| AIAgentRegister_CL (pack table) | Log Analytics ingestion and retention charges; low volume | https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview |
| CopilotActivity | Microsoft Copilot connector (Sentinel solution) | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/copilotactivity |
| NetworkAccessTraffic | Entra Internet Access (Global Secure Access) licence | https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-view-traffic-logs |
| AGWFirewallLogs, AGWAccessLogs | App Gateway WAF_v2, diagnostics in resource-specific mode | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/agwfirewalllogs |
| ThreatIntelIndicators | Sentinel threat intelligence (optional enrichment) | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/threatintelindicators |

**Starting point:** D04, D05, D07, PB1, the register, workbook and PB5 use Entra ID P1 and Sentinel. PB4 also needs Defender XDR.


## Deploy (lab only until validated)

Deploy in this order. The register comes first because D04 and D05 read the approved watchlist.

```bash
az deployment group create -g <rg> -f deploy/register-infra.json -p workspaceName=<ws>      # table, DCR, watchlists, functions
az deployment group create -g <rg> -f deploy/workbook.json -p workspaceName=<ws>
az deployment group create -g <rg> -f deploy/analytics-rule-D04.json -p workspace=<ws> ruleId=<fixed-guid>
az deployment group create -g <rg> -f deploy/playbook-PB1-agent-containment.json -p TeamsGroupId=<id> TeamsChannelId=<id>
az deployment group create -g <rg> -f deploy/automation-rule-D04-PB1.json -p workspace=<ws> analyticsRuleResourceId=<id> playbookResourceId=<id>
az deployment group create -g <rg> -f deploy/playbook-PB4-register-sync.json -p LogsIngestionEndpoint=<output> DcrImmutableId=<output>
az deployment group create -g <rg> -f deploy/playbook-PB5-ism-evidence-export.json -p WorkspaceId=<guid> StorageAccountName=<sa>
```

After deploying:
1. Grant each playbook's managed identity its roles (listed in each PB doc).
2. Authorise the Teams connection.
3. Enable the Logic Apps.

Rules deploy **disabled**, and the Logic Apps deploy in the **Disabled** state.

`register-infra.json` and `workbook.json` are compiled from `deploy/bicep/*.bicep`, which load the KQL, CSV and workbook files with `loadTextContent`.

To regenerate, run:

```bash
python3 tools/build_workbook.py && python3 tools/build_arm.py && bicep build deploy/bicep/register-infra.bicep --outfile deploy/register-infra.json && bicep build deploy/bicep/workbook.bicep --outfile deploy/workbook.json
```


## Known limits

- **No live run.** Nothing has run against real data or been deployed, and thresholds need tuning.
- **JSON keys inside dynamic or string columns:** `agentType` in `TargetResources` and `InitiatedBy.app`; `agentType` and `parentAppId` inside `AADServicePrincipalSignInLogs.Agent`; `DelegatedPermissionGrant.Scope`.
- **String values:** CloudAppEvents exfil ActionTypes; Copilot Studio protection alert titles; ClientCredentialType strings; AgentsInfo `SharedWith` values; NetworkAccessTraffic agentic column population.
- **Copilot identifiers:** whether `CopilotActivity.ActorUserId` is the Entra object ID.
- **PB1:** the incident `Custom Details` expression and the adaptive card response shape.
- **PB4:** how `runHuntingQuery` returns dynamic columns.
- **PB5:** the `tables[0].rows[0][0]` response path.
- **Logic Apps:** the workflow definitions aren't schema-validated.
- **Workbook:** rendering (formatters, tiles, tabs) hasn't been opened in a portal.
- **Functions:** whether saving a function that references a missing table succeeds. The functions use `union isfuzzy=true` to tolerate missing tables at run time.
- **Markdown summary:** the `serialize` + `make_list` ordering in `YumaEvidenceMarkdown()`.
- **Design only:** PB2 and PB3.

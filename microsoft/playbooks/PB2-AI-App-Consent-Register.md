# PB2 AI App Consent to Register

**Fires on:** D05 (new AI app consent).
**Built as:** a Logic App with the Sentinel incident trigger, started by an automation rule.
**Writes to:** the Sentinel register table `AIAgentRegister_CL`, through the Logs Ingestion API, and to the watchlist `YumaAIRegisterApproved`. Both are deployed by `../deploy/register-infra.json`.
**Controls:**
- ISM-2134 and ISM-2135 (agent register)
- ISM-2137 (no user consent)
- ISM-2138 (review every six months)
- ISM-2139 (log consent)
- ISM-2113 (human decision)

## Flow

1. **Trigger.** An incident from D05.
   - Entities: the consenting user's Account and IP.
   - Custom details: AppSpId, AppName, Scopes, IsUserConsent.
2. **Enrich with Graph:**
   - `GET /v1.0/servicePrincipals/{id}` for `appId`, `verifiedPublisher` and `appOwnerOrganizationId`.
   - `GET /v1.0/servicePrincipals/{id}/owners`.
   - `GET /v1.0/servicePrincipals/{id}/oauth2PermissionGrants` to list the delegated grants.
3. **Write a `RegisterSnapshot` record** to the stream `Custom-AIAgentRegister` with these fields:
   - `RecordType = RegisterSnapshot`
   - `Source = EntraConsent`
   - `AgentKey = <service principal object ID>`
   - `AppId`, `ServicePrincipalId`, `Owners`, `Permissions` (the scopes), `Identities`

   POST `{logsIngestionEndpoint}/dataCollectionRules/{dcrImmutableId}/streams/Custom-AIAgentRegister?api-version=2023-01-01` with a managed identity token for `https://monitor.azure.com`. The managed identity needs Monitoring Metrics Publisher on the DCR.
   https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview
4. **Teams approval** to the AI system owner. The card asks for:
   - a decision: approve, revoke or investigate
   - the business purpose (free text, which fills the ISM-2135 purpose field)
   - a risk rating
5. **Write a `ConsentDecision` record** with:
   - Decision, DecisionBy (the responder's UPN), DecisionReason
   - BusinessPurpose, RiskRating
   - ConsentType, IsAdminConsent, ConsentedBy, ConsentDate
   - IncidentArmId

   `YumaAIRegister()` treats the decision time as the latest review date, which starts the six-month clock.
6. **If approved,** upsert the watchlist item in `YumaAIRegisterApproved` (SearchKey = service principal object ID) so that D04 and D05 stop alerting on it.
   https://learn.microsoft.com/en-us/rest/api/securityinsights/watchlist-items/create-or-update
7. **If revoke is chosen,** which happens only after a human selects it:
   - `DELETE /v1.0/oauth2PermissionGrants/{id}` for delegated grants
   - `DELETE /v1.0/servicePrincipals/{resourceSpId}/appRoleAssignedTo/{assignmentId}` for application permissions
   - then comment on the incident and close it as a true positive
8. **If it was user consent,** add a comment recommending the tenant setting that blocks user consent (ISM-2137).

## Six-monthly review (PB2-Review, recurrence, design)

- **Daily run.** Query `YumaAIRegister() | where ReviewStatus in ("Overdue", "Due within 30 days", "Never reviewed")` through the Logs query API (`https://api.loganalytics.azure.com/v1/workspaces/{id}/query`).
- **Owner card.** Post one Teams card per owner, asking them to keep, reduce or revoke the app.
- **Record the outcome.** Write a `ReviewCompleted` record with DecisionBy and DecisionReason, or a `Retired` record if the app is removed. These records are the ISM-2138 evidence that PB5 exports.

## Permissions

| Need | Permission | Source |
|---|---|---|
| Write register records | Monitoring Metrics Publisher on the DCR | https://learn.microsoft.com/en-us/azure/azure-monitor/logs/tutorial-logs-ingestion-api |
| Update the watchlist | Microsoft Sentinel Contributor on the workspace | https://learn.microsoft.com/en-us/rest/api/securityinsights/watchlist-items/create-or-update |
| Delete delegated grants | DelegatedPermissionGrant.ReadWrite.All | https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-delete |
| Remove app role assignments | AppRoleAssignment.ReadWrite.All | https://learn.microsoft.com/en-us/graph/api/serviceprincipal-delete-approleassignedto |

## Unvalidated

- There's no ARM template yet; this is a design only. The ingestion call matches the one in PB4's ARM, so PB4 can be used as the pattern.
- The revoke permissions are themselves high-risk, so use the same separation advice as PB1.

# PB1 Agent Permission Containment

**Fires on:** D04 (high-risk Graph permission to an AI agent or app), D07 (agent sign-in anomaly), D08 (agent Graph data burst).
**Built as:** a Logic App (Consumption) with the Microsoft Sentinel incident trigger, started by an automation rule.
**ARM skeleton:** `../deploy/playbook-PB1-agent-containment.json`. Automation rule: `../deploy/automation-rule-D04-PB1.json`.
**Controls:** ISM-2113 (human approval before high-impact action), ISM-2146 and ISM-2148 (revoke credentials and sessions), ISM-2156.

## Flow

1. **Trigger.** Sentinel incident created by D04, D07 or D08. The automation rule matches on `IncidentRelatedAnalyticRuleIds`.
2. **Get the service principal ID** from the alert custom detail `ClientSpId` (D04) or `ServicePrincipalId` (D07, D08).
3. **Enrich with Graph** using the Logic App's managed identity:
   - `GET /v1.0/servicePrincipals/{id}`
   - `GET /v1.0/servicePrincipals/{id}/owners`
   - `GET /v1.0/servicePrincipals/{id}/appRoleAssignments`
4. **Comment on the incident** with the enrichment.
5. **Ask a human.** Use Teams "Post adaptive card and wait for a response" to the SOC channel. The choices are:
   - disable the service principal
   - keep it enabled and monitor
   - close it as expected

   v2 adds a direct card to the app owner pulled from the owners call.
6. **Act on the answer.**
   - **Disable:** `PATCH /v1.0/servicePrincipals/{id}` with `{"accountEnabled": false}`, then comment. Disabling stops new tokens, but existing access tokens stay valid until they expire. The comment tells the analyst to revoke grants and rotate credentials as follow-up.
   - **Expected:** comment and remind the analyst to add the app to the D04 allow-list and the agent register.
   - **Keep:** comment and flag it for the next six-monthly consent review (ISM-2138).

## Permissions (least privilege first)

| Need | Permission | Source |
|---|---|---|
| Read the service principal, owners and assignments | Application.Read.All (app) | https://learn.microsoft.com/en-us/graph/api/serviceprincipal-get |
| Disable a service principal | Application.ReadWrite.OwnedBy (least, only for apps the identity owns). Higher: Application.ReadWrite.All. For agent identities: AgentIdentity.ReadWrite.All | https://learn.microsoft.com/en-us/graph/api/serviceprincipal-update |
| Comment on and update incidents | Microsoft Sentinel Responder on the workspace (managed identity) | https://learn.microsoft.com/en-us/azure/sentinel/automation/authenticate-playbooks-to-sentinel |
| Let Sentinel run the playbook | Microsoft Sentinel Automation Contributor on the playbook resource group | https://learn.microsoft.com/en-us/azure/sentinel/automation/automate-responses-with-playbooks |

**Risk to flag to customers.** Application.ReadWrite.All is itself a high-risk permission and D04 would flag it. Offer two options:
- Grant it to a dedicated playbook identity, protect that identity, and document it in the register.
- Run disable-only through a PIM-activated Cloud Application Administrator.

## Unvalidated

- The expression that reads `Custom Details` from the incident payload (`Alerts[0].properties.additionalData['Custom Details']`).
- Whether disabling works the same way on Entra Agent ID agent identities as on classic service principals.
- The adaptive card response shape (`body(...)['data']['decision']`). It follows Microsoft's GCP-DisableServiceAccountFromTeams playbook, but hasn't been run.
- Nothing has been deployed.

References:
- https://learn.microsoft.com/en-us/connectors/teams/
- https://learn.microsoft.com/en-us/azure/sentinel/surface-custom-details-in-alerts

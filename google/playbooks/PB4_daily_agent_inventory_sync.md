# PB4: Daily AI agent inventory sync

**Fires on:** Cloud Scheduler at 02:15 AEST/AEDT, daily.

**Controls:** ISM-2134 (register maintained and regularly verified), ISM-2135 (register contents), ISM-2133 (identity type)

## Flow (`workflows/pb4-inventory-sync.yaml`)

1. Cloud Asset `searchAllResources` at org scope, once per asset type:
   - `aiplatform.googleapis.com/ReasoningEngine` (Agent Runtime, formerly Agent Engine)
   - `discoveryengine.googleapis.com/Engine` and `discoveryengine.googleapis.com/Assistant` (Gemini Enterprise)
2. For each Reasoning Engine, call `reasoningEngines.get` and record the following from `spec`:
   - `spec.identityType`: SERVICE_ACCOUNT, AGENT_IDENTITY or unspecified
   - `spec.effectiveIdentity`
   - `spec.serviceAccount`
   - `spec.agentFramework`
   - `spec.classMethods[].name`, as the declared tools
3. Insert a `RegisterSnapshot` row for each.
4. `CALL sp_workspace_oauth_snapshot()`. This adds a snapshot for every Workspace OAuth client still holding grants (authorize minus later revoke, over 90 days).
5. `v_register_current` computes the gap flags:
   - `gap_no_unique_identity`, meaning any of: shared service agent, a service account shared by several agents, or domain-wide delegation
   - missing owner, purpose, permissions, tools or data sources
   - `review_status`
   - `stale_in_sync`
6. `v_ai_service_accounts` feeds G06, G07 and G15. Export it to the SecOps reference list `%yuma_ai_service_accounts` (see Unvalidated).

## A. SecOps SOAR

Run it as a scheduled SOAR job:
- Cloud Asset Inventory *Enrich Resource*, or HTTP v2 for `searchAllResources`
- BigQuery *Run SQL Query* to write rows

## Add once confirmed in a lab

- **Agent Registry** (`agentregistry.googleapis.com` v1): `projects.locations.agents.list` and `mcpServers.list`, giving skills, card, protocols and MCP tools. These fill `declared_tools` and `mcp_servers`.
- **Gemini Enterprise** v1alpha: `.../assistants/{a}/agents`, giving sharingConfig and authorizationConfig. These fill `shared_with`.
- **Updating the SecOps reference list** through the Chronicle API.

## Permissions

| Principal | Role | Risk |
|---|---|---|
| yuma-gai-pb4 | roles/cloudasset.viewer, roles/aiplatform.viewer, roles/discoveryengine.viewer (org) | low (read) |
| yuma-gai-pb4 | BigQuery dataEditor (register), jobUser, dataViewer (Workspace export) | low |

## Unvalidated

- Not executed.
- Workflows has no Cloud Asset connector, so the call is plain HTTP.
- The `project_id` written is Cloud Asset's `projects/NUMBER` form.
- Owners, purpose and data sources can't be discovered. They come from PB2 and owner input, and the gap flags show what's missing.

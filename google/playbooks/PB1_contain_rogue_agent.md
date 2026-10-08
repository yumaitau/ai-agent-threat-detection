# PB1: Contain a rogue AI agent, AI service account or OAuth app (human approval first)

**Fires on:**
- G06: sensitive role granted to an AI identity
- G07: static key created for an AI service account
- G01 and G04: AI OAuth app consent or data-pull burst
- G08: injection followed by an action
- G15: AI service-account key used off Google
- SCC AI Protection findings, for example "IAM Anomalous Grant to Agentic Identity" or "Agentic Identity Credential Used Outside of Google Cloud"

**Controls:**
- ISM-2113: a human approves before any high-impact action
- ISM-2144, ISM-2146 and ISM-2148: change or revoke compromised credentials, keys and tokens
- ISM-2156 and ISM-2157
- E8: restrict administrative privileges

## Proposed actions, by entity

| Entity | Action | API (checked against the discovery docs) |
|---|---|---|
| Service account an agent runs as | Disable the service account | `iam.projects.serviceAccounts.disable` (`POST v1/{name}:disable`) |
| User-managed key on an AI service account | Disable the key | `iam.projects.serviceAccounts.keys.disable` |
| Agent Identity (`principal://agents.global...`) | Roll back the binding that was just added (project level) | `cloudresourcemanager v3 projects.getIamPolicy` / `setIamPolicy` |
| Workspace OAuth app | Revoke the app's token for each affected user | Directory API `tokens.delete` (`DELETE admin/directory/v1/users/{userKey}/tokens/{clientId}`), scope `admin.directory.user.security` |
| Gemini Enterprise agent | Notify only. Disable it in the Gemini Enterprise console | No containment API was verified |

Agent identities can't be disabled the way a service account can. Google designed them so they can't be impersonated and can't hold keys (https://docs.cloud.google.com/iam/docs/agent-identity-overview). Containment therefore means removing what the identity was granted.

## A. Google SecOps SOAR design

Built from integrations listed in Google's SOAR integration catalogue (https://google.github.io/mcp-security/soar_integrations/):

1. **Trigger.** A case is opened from a G-rule detection or an SCC finding. Map the entities: the user, the service account as a `USERUNIQNAME` entity, the OAuth client ID as a custom entity, and the IP.
2. **Enrich.**
   - Google Cloud IAM: *Enrich Entities* and *Get Service Account IAM Policy*.
   - Cloud Asset Inventory: *List Service Account Roles*.
   - BigQuery: *Run SQL Query* against `v_register_current`, to get the owner, purpose and approval state.
3. **Approval.**
   - Slack: *Ask Question*, then *Wait For Reply*. Or Email V2: *Send Email*, then *Wait for Email from User*.
   - The approver's identity and answer go into the case wall. Google Chat (*Send Message*) is notify-only because it has no wait-for-reply action.
   - SOAR's built-in manual approval step can be used instead.
4. **Act** (only on approval).
   - Google Cloud IAM: *Disable Service Account*.
   - Key disable and OAuth token revoke have no packaged action. Use **HTTP v2 – Execute HTTP Request** against the two REST calls in the table above, authenticated as a dedicated service account.
   - The G Suite integration has *Revoke User Session* but no token revoke.
5. **Record.**
   - BigQuery: write a `ContainmentDecision` row (decision, decision_by, reason, case ID) to `ai_agent_register`.
   - Close the loop on SCC with *Update Finding*.

## B. No-SecOps path (shipped skeleton)

`workflows/pb1-containment.yaml`, `functions/approval`, `functions/revoke_oauth_token`, `deploy/terraform/{detections,playbooks,iam}.tf`

1. The org log sink (`yuma-gai-ai-identity-changes`) catches key creation and AI-identity `SetIamPolicy` ADDs. The flow is Pub/Sub, then Eventarc (`google.cloud.pubsub.topic.v1.messagePublished`), then the Workflow. Other detections can start the workflow directly with a normalised request.
2. For G07, the workflow checks `v_ai_service_accounts` and ignores keys on service accounts that aren't AI.
3. `events.create_callback_endpoint` posts to Google Chat (an incoming webhook stored in Secret Manager) with a link to the **approval service**.
   - The approval service is a Cloud Run function behind IAP. It verifies the IAP JWT and takes the approver's email from it.
   - It POSTs `{decision, approver, reason}` to the callback.
4. `events.await_callback` waits for one hour by default. A timeout means no action.
5. On *Approve*, the workflow does one of four things:
   - disables the service account
   - disables the key
   - rolls back only the AI-member bindings ADDed in the triggering change
   - calls the revoke function
6. A `ContainmentDecision` row goes to the register, and the outcome is posted to Chat.

Slack or email instead of Chat: swap the webhook secret for a Slack incoming webhook. The approval link and IAP step stay the same, so the approver is still identified by IAP rather than by chat.

## Permissions

The playbook is itself a powerful agent. Register it.

| Principal | Role | Why | Risk |
|---|---|---|---|
| yuma-gai-pb1 | roles/iam.serviceAccountAdmin (org) | disable service accounts | HIGH |
| yuma-gai-pb1 | roles/iam.serviceAccountKeyAdmin (org) | disable keys | HIGH |
| yuma-gai-pb1 | roles/resourcemanager.projectIamAdmin (org) | roll back bindings | HIGH |
| yuma-gai-pb1 | BigQuery dataEditor (register) + jobUser; secretAccessor (webhook) | register, notify | low |
| yuma-gai-fn-revoke | Token Creator on itself + Workspace domain-wide delegation for `admin.directory.user.security`, impersonating a dedicated admin with a user-security-only custom role | revoke OAuth tokens | HIGH |
| yuma-gai-fn-approval | roles/workflows.invoker | send callback | low |

## Unvalidated

- Nothing has been deployed or executed.
- Keyless domain-wide delegation via signJwt in `revoke_oauth_token` is a known pattern but untested here.
- IAP in front of a Cloud Run function (`approval`) needs a load balancer or Cloud Run's direct IAP. That setup is manual and not in Terraform.
- The sink filter regex and the exact LogEntry JSON shape Eventarc delivers to Workflows need checking on one real event.

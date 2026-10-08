# Google Cloud and Workspace

Detections, response playbooks and an AI agent register for Google Cloud and Workspace.

**Validation status:** the implementation passes the offline checks listed in [validation](../docs/validation.md). It has **NOT been tested against live tenants or accounts**. Tune thresholds against representative data before enabling alerts or response actions. Some entries are draft hunts or specifications.

See the [combined detection catalogue](../mappings/README.md) for all 15 entries on this platform and their original framework mappings.

## Detection setup

**Reference lists** for SecOps; the BigQuery path uses register views instead:
- `%yuma_ai_approved_oauth_clients`
- `%yuma_ai_service_accounts`
- `%yuma_ai_registered_agents`
- `%yuma_gemini_approved_users`
- `%yuma_ai_approved_workloads`

**How the BigQuery path runs:** each query outputs `severity, entity, summary` plus detail columns. Terraform wraps each one in an `INSERT INTO detection_hits … TO_JSON(t)` with a per-entity suppression window, and schedules it. The rule-grade queries run every hour, or every 10 minutes for G13. Hunts run daily if `enable_hunts = true`.


## Playbooks

| # | Purpose | SecOps SOAR (catalogue actions) | No-SecOps (shipped skeleton) | Human approval |
|---|---|---|---|---|
| PB1 | Contain a rogue agent, service account or OAuth app | IAM *Disable Service Account*; HTTP v2 for key disable and Directory `tokens.delete`; Slack *Ask Question* / Email *Wait for Email*; Chat notify | Org sink → Pub/Sub → Eventarc → Workflow; callback + IAP approval service records the approver; IAM / CRM REST calls; revoke function (keyless DWD) | **Yes** (ISM-2113) |
| PB2 | New AI consents and agents → register → decision; six-monthly review | BigQuery *Run SQL Query*; Slack / Email ask | Hourly scheduled query adds `Pending` decisions; reviews-due query; approve or revoke via PB1 approval | Yes |
| PB3 | Enrich attacking IPs (GreyNoise, AbuseIPDB, ThreatFox) → Cloud Armor deny with expiry | Cloud Armor *Add a Rule to a Security Policy* | Scheduled Cloud Run function: verdict → `addRule` (SRC_IPS_V1, ≤10 IPs per rule, priority band, `expires=`) → hourly `removeRule` cleanup | No (low impact, reversible, expires) |
| PB4 | Daily agent inventory sync | Scheduled job: HTTP v2 Cloud Asset + BigQuery | Workflow: Cloud Asset `searchAllResources` → `reasoningEngines.get` (identityType, effectiveIdentity, serviceAccount, framework, classMethods) → register; Workspace OAuth snapshot procedure | No |
| PB5 | Monthly ISM evidence export | BigQuery + Cloud Storage *Upload an Object* | Workflow: `EXPORT DATA` CSVs + `summary.md` + `manifest.json` to a retention-locked bucket | No |

The PB1, PB3 and revoke-function identities are **high-risk agents themselves**. The permissions table in each playbook flags them. Register them, and keep PB1's approval step.


## Register and ISM evidence

- **`ai_agent_register`** (BigQuery, append-only) has these record types:
  - `RegisterSnapshot` (PB4)
  - `ConsentDecision` (PB2)
  - `ContainmentDecision` (PB1)
  - `ReviewCompleted`
  - `Retired`

  Its fields cover everything ISM-2135 asks for: identifier, owner, business purpose, identities, user accounts and credentials, permissions, tools, MCP servers, data sources. It also records `identity_type` / `effective_identity` for ISM-2133, and decision, decided-by and reason for ISM-2113.
- **`v_register_current`**: the latest state per agent, with gap flags (`gap_no_unique_identity`, owner, purpose, permissions, tools, data sources), `review_status` for ISM-2138, and `stale_in_sync`.
- **`v_ism_control_status`**: Met / Gap / Partial / Attestation required for each of the 12 controls. The verbatim control text is from ISM 2026.09 (ACSC OSCAL) and lives in `register/ism_control_map.csv`.
- **PB5** writes `gs://…/ism-evidence/YYYY-MM/` monthly.
- **Dashboards:** see `dashboard/` for the outlines (Looker Studio: 4 pages; SecOps: 7 panels).


## Licence and data prerequisites

| Need | For | Notes |
|---|---|---|
| Org-level aggregated log sink to a Log Analytics bucket, with a linked BigQuery dataset | All SQL detections on `_AllLogs` | Admin Activity is on by default. **Data Access logs must be enabled** for aiplatform (G10), iamcredentials and bigquery (G08 follow-on actions) |
| Workspace **BigQuery export** | G01, G02, G04, G05, PB2, PB4 | Needs a Workspace edition that supports it (check https://support.google.com/a/answer/9079365) |
| Model Armor with `log_sanitize_operations` on templates / floor settings | G08 | Model Armor usage is billed by Google |
| Cloud DNS query logging; VPC Flow Logs | G11, G12 | Logging cost |
| External Application Load Balancer + Cloud Armor, request logging on | G13, G14, PB3 | |
| Google SecOps (optional) | YARA-L rules, SOAR path | Add Data Access, `GCP_LOADBALANCING` (`requests`) and `GCP_MODEL_ARMOR` logs to the export filter. By default only Admin Activity, System Event and DNS are sent |
| SCC Premium (optional, recommended) | Complements G06, G10, G15 with Google's AI Protection findings | The pack works without it |
| TI keys | PB3 | AbuseIPDB and ThreatFox (Auth-Key) are free tiers; GreyNoise Community |


## Deploy (lab first)

1. **Prepare the data.**
   - Upgrade the org aggregated log bucket to Log Analytics and link a dataset.
   - Turn on the Workspace BigQuery export.
   - Enable the Data Access logs listed in Licence and data prerequisites.
2. **Run Terraform.** In `deploy/terraform`, copy `terraform.tfvars.example` to `terraform.tfvars`, then run `terraform init && terraform plan`.
   - Review the plan, then apply it in a lab. The configuration creates the register dataset, tables and views, 6 scheduled detections, the PB2 query, the org sink, topic, Eventarc trigger, PB1/PB4/PB5 workflows, 3 functions, scheduler jobs, empty secrets, the evidence bucket and IAM.
3. **Add the secrets out of band.** Load the Chat webhook and the 3 TI keys into Secret Manager.
4. **Seed the approved apps:** `bq load` `register/approved_apps.csv` into `approved_apps`.
5. **Approval service.** Put `yuma-gai-approval` behind IAP, restricted to the approver group. Set `approval_url` and `approver_iap_audience`, then run apply again.
6. **Set up the revoke path in Workspace.**
   - Create a dedicated admin user with a custom role limited to user security.
   - Authorise the `yuma-gai-fn-revoke` client ID for `https://www.googleapis.com/auth/admin.directory.user.security` under domain-wide delegation.
   - Record it in the register.
7. **SecOps path** (optional).
   - Create the 5 reference lists, then load `detections/secops/*.yaral` as rules.
   - Start with alerting off, and replay 30 days of data.
8. **Check offline before every change:** `bash tools/validate_all.sh`.


## Known limits

- **No live run of anything.** Thresholds need tuning.
- **Workspace export literals:** `record_type='token'` / `'admin'` / `'gemini_in_workspace_apps'` and `event_name` values. `token.num_response_bytes` / `product_bucket` (G04 has them commented out). The admin DWD parameter columns.
- **SecOps:** whether `labels["scope"]` matches one of several same-key labels (G01); GCP_MODEL_ARMOR verdict wording and project field (G08 YARA-L); `count_distinct` over a label map (G13); `metadata.product_name` values `token` and `gemini_in_workspace_apps`.
- **Method names:** `ReasoningEngineService.Create/UpdateReasoningEngine` audit method names (proto-derived, not on Google's audited-operations page), and the Gemini Enterprise agent method names (G09).
- **Model Armor paths:** `json_payload.sanitizationResult…` in `_AllLogs`, and the labels JSON key access (G08 SQL).
- **Playbooks:**
  - Keyless DWD in the revoke function.
  - IAP in front of the approval function (manual).
  - The LogEntry shape delivered by Eventarc to PB1.
  - PB1's binding rollback logic.
  - PB5's `EXPORT DATA` via the `jobs.insert` connector.
  - Live TI API responses.
- **Design only:** the Looker Studio and SecOps dashboards; the PB2 approval workflow; Agent Registry and Gemini Enterprise ingestion in PB4; the SecOps reference-list sync.

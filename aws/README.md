# AWS

Detections, response playbooks and an AI agent register for AWS.

**Validation status:** the implementation passes the offline checks listed in [validation](../docs/validation.md). It has **NOT been tested against live tenants or accounts**. Tune thresholds against representative data before enabling alerts or response actions. Some entries are draft hunts or specifications.

See the [combined detection catalogue](../mappings/README.md) for all 15 entries on this platform and their original framework mappings.

## Detection setup

**Log prerequisites (environment, charged by AWS):**
- A multi-Region trail. For A10 and A11, CloudTrail data events need advanced selectors for `AWS::Bedrock::Guardrail`, `AWS::Bedrock::AgentAlias`, `AWS::Bedrock::KnowledgeBase`, `AWS::BedrockAgentCore::Gateway` and `AWS::S3::Object` (Bedrock types: https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html; Gateway: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/enabling-cloudtrail-data-event-logging.html)
- A CloudTrail Lake event data store (A03 backfill, A10, A11), or the trail delivered to CloudWatch Logs (A11 Logs Insights variant).
- Security Lake with CloudTrail management, S3 data, Route 53 and WAF sources (A01, A02, A04 to A08, A14), or the CloudWatch Logs variants.
- Bedrock model invocation logging to CloudWatch Logs (A02).
- WAF logging to CloudWatch Logs (A13, A14).
- GuardDuty AI Protection.


## SOAR playbooks

| PB | Trigger | Flow | Deliverable |
|---|---|---|---|
| **PB1 Agent identity containment** | A04 (EventBridge, us-east-1), GuardDuty AI Protection findings, scheduled detections | Enrich (GetRole trust policy + register) -> not an agent: notify only -> `lambda:invoke.waitForTaskToken` posts to SNS email and optional Slack/Teams webhook with an AWS CLI approve/reject command (4 h timeout) -> on approve: inline deny policy `YumaAIAContainment` (deny-all or revoke sessions via `aws:TokenIssueTime`) or deactivate IAM user keys -> register ApprovalDecision -> notify | **ASL** `playbooks/asl/PB1-agent-containment.asl.json`, 3 Lambdas, **CloudFormation** |
| **PB2 Register writer** | A03 EventBridge rule; weekly review sweep | ChangeObserved history -> upsert CURRENT as PendingReview (never overwrites a decision) -> identity map -> email with `register_decide.py` command; sweep emails owners of reviews due within 30 days | Lambda, **CloudFormation**, `tools/register_decide.py` |
| **PB3 WAF enrich and block** | Every 15 min | A14 Logs Insights -> allow-list -> GreyNoise Community, AbuseIPDB, ThreatFox -> score -> propose, or (if pre-approved) `GetIPSet` + `UpdateIPSet` with `LockToken` -> expiry tracked in DynamoDB | Lambda, **Terraform** skeleton |
| **PB4 Daily inventory sync** | Daily 06:30 Sydney time | Bedrock Agents, AgentCore runtimes, gateways, workload identities, credential providers, AWS Agent Registry records, IAM roles trusted by Bedrock/AgentCore -> PendingReview for unregistered -> S3 JSON Lines snapshots -> Logs lookup table -> metrics | Lambda, **CloudFormation** |
| **PB5 Monthly ISM evidence export** | 1st of the month, 07:00 Sydney time, or on demand | Register + logging posture (invocation logging, trail data-event selectors, GuardDuty AI Protection) -> `agent-register.csv`, `ism-controls.csv`, `summary.md`, `manifest.json` (SHA-256) -> Object Lock bucket | Lambda, **CloudFormation** |

Every destructive step sits behind a named human decision, except PB3 auto-block, which you must switch on (`AUTO_BLOCK=true`). The containment role has an explicit Deny on the pack's own roles, Identity Center roles and `OrganizationAccountAccessRole`. Add break-glass roles before go-live.


## AI agent register and ISM evidence (all inside your AWS account)

| Piece | What it is | File |
|---|---|---|
| DynamoDB table `YumaAIAgentRegister-<region>` | `pk = AGENT#<id>`, `sk = CURRENT` or `HIST#<time>#<RecordType>` (append-only history: RegisterSnapshot, ChangeObserved, ApprovalDecision, ReviewCompleted, Retired). `IDENTITY#<arn>` items map roles to agents; `WAFBLOCK` items hold PB3 blocks. GSI `by-status-review`. PITR, encryption, deletion protection | `register/dynamodb-register.json`, `register/register-record.schema.json` |
| ISM-2135 fields | agent_id, owner, business_purpose, identities, credentials, tools, permissions, data_repositories (plus approved_models, decided_by, last_review, next_review_due at 182 days) | same |
| Athena | `register_snapshots` and `inventory` (partition projection, no crawler), views `register_current`, `register_identities`, `register_ism` | `register/athena-register.sql` |
| ISM control map | ISM-2133 to 2140 and 2156 to 2159: control text, pack evidence, evidence method | `register/ism-control-map.csv` |
| Dashboard | CloudWatch dashboard: register metrics, trend, A01, A02, A11, A13 widgets | `register/cloudwatch-dashboard.json` |
| QuickSight | Optional outline for executive or assessor reporting | `register/quicksight-outline.md` |
| Evidence export | PB5 dated folder in an S3 Object Lock (compliance mode) bucket | `playbooks/PB5-ism-evidence-export.md` |

The register is an evidence source to support an assessment. It isn't a compliance determination: "Attestation required" controls still need a written statement from the control owner.


## Deploy (lab only until validated)

1. Turn on the logs in Detection setup: trail data-event selectors, model invocation logging, WAF logging, GuardDuty AI Protection.
2. `python3 tools/package_lambdas.py`. Bundle a current boto3 into `build/` first if the runtime lacks the AgentCore or Agent Registry clients. Then `aws s3 sync dist/ s3://<artifact-bucket>/yuma-aia/0.1.0/`.
3. Deploy `deploy/cfn/yuma-aia-core.yaml` in the workload Region. Deploy it again in **us-east-1** for the A04 IAM rule (the rule is conditional on that Region).
4. Create the Logs lookup table `yuma_aia_register` (console or `CreateLookupTable`) and pass its ARN to the stack.
5. Run the Athena DDL in `register/athena-register.sql`. Import `register/cloudwatch-dashboard.json` after setting the log group names.
6. `terraform apply` in `deploy/terraform/pb3-waf-block/` with `auto_block = false`. Add the rule group to the web ACL.
7. Schedule the SQL detections: EventBridge Scheduler -> Lambda -> Athena `StartQueryExecution` or CloudTrail `StartQuery`, with results to SNS or PB1. This runner isn't in the draft yet; it remains to be implemented.


## Known limits

- **No live run.** Nothing has been deployed or run against real data, and thresholds need tuning.
- **Security Lake 2.0 field names for Route 53** (`query.hostname`, `src_endpoint.instance_uid`) come from AWS's OCSF 1.0 samples. `actor.session.issuer` for assumed-role sessions and the s3_data_2_0 fields are assumed to be the same as the CloudTrail management table.
- **The Agent Registry event source** `agent-registry.amazonaws.com` and the IAM prefix `agent-registry:` are inferred from the service's signing name.
- **EventBridge matching of array-of-object paths** (A10 `assessments[].contentPolicy.filters[].type`) works in the local tester, but AWS evaluates each leaf over the flattened array, so it could be looser live.
- **The A11 Logs Insights flattening** of `requestParameters.body.*` (a JSON object inside CloudTrail) has not been seen in a real log group.
- **CloudTrail Lake:** WITH clauses were avoided because AWS samples only show subqueries; `date_add` on `eventTime` is assumed to work because `eventTime` is a timestamp.
- **A15 field names** (grant type, client) are unknown.
- **No AWS setting was found to disable device authorisation in Identity Center** (ISM-2140). This is an open question.
- **Not wired in the draft:** the dashboard rendering, the QuickSight outline, the scheduled-detection runner, multi-account PB4 and the A05 to PB2 routing.

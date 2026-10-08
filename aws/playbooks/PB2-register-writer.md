# PB2 New AI agent, tool or credential: write to the register

**Trigger:** EventBridge rule `A03-agent-or-tool-change.eventbridge.json`, which matches CloudTrail management events.
- **Bedrock Agents:** CreateAgent, UpdateAgent, action groups, aliases, knowledge base and collaborator associations.
- **AgentCore:** runtimes, endpoints, gateways and gateway targets, workload identities, OAuth2 and API key credential providers, memory, browser, code interpreter, harness.
- **AWS Agent Registry records.** The event source for these is unverified.

**Flow** (`pb2_register_writer.py`):
1. Resolve the new resource ARN from `responseElements` (falling back to `resources[0].ARN`) and the role from
   `requestParameters.roleArn` or `agentResourceRoleArn`.
2. Write a `ChangeObserved` history item. Upsert the `CURRENT` item: status is set to PendingReview only if the item is new,
   so a human decision is never overwritten. The role goes into the `identities` string set. An identity map item
   (`IDENTITY#<role arn>`) lets PB1 and the detections find the agent from a role.
3. Email the register topic with the exact `tools/register_decide.py` command to approve or reject. Approving
   records owner, purpose, tools, permissions, data repositories, credentials and approved models. Those are the
   ISM-2135 fields. It also sets `next_review_due` to 182 days later.

**Six-monthly review job:** EventBridge Scheduler runs `{"action": "review-sweep"}` every Monday at 08:00 Sydney time.
It queries the `by-status-review` index for Approved agents due within 30 days and emails owners. Running
`register_decide.py --decision review` records a `ReviewCompleted` item (ISM-2138 cadence applied to agents).

**Identity Center apps (A05)** are routed to the same register by adding A05's pattern as a second rule on PB2
(not wired in the CloudFormation draft yet).

**ISM:** 2134, 2135, 2138, 2113. **Deployed by:** `deploy/cfn/yuma-aia-core.yaml`.

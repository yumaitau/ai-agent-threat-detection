# PB4 Daily AI agent inventory and register sync

**Trigger:** EventBridge Scheduler, daily 06:30 Sydney time.

**Inventory** (`pb4_inventory.py`, operation names checked against botocore models):

| Source | Calls |
|---|---|
| Bedrock Agents | `bedrock-agent` ListAgents, GetAgent (`agentResourceRoleArn`) |
| AgentCore runtimes | `bedrock-agentcore-control` ListAgentRuntimes, GetAgentRuntime (`roleArn`, workload identity) |
| AgentCore gateways | ListGateways, GetGateway (`roleArn`, `authorizerType`, `webAclArn`) |
| Workload identities | ListWorkloadIdentities |
| Credentials | ListOauth2CredentialProviders, ListApiKeyCredentialProviders |
| AWS Agent Registry | `agent-registry-control` ListRegistries, ListRegistryRecords (discovery catalogue: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/registry.html) |
| IAM | ListRoles; any role whose trust policy names `bedrock.amazonaws.com` or `bedrock-agentcore.amazonaws.com` |

**Then:**
1. Anything not in the register (by resource ARN or by identity) is added as PendingReview, with a RegisterSnapshot history item.
2. JSON Lines snapshots go to `inventory/snapshot_date=YYYY-MM-DD/` and `register/snapshot_date=YYYY-MM-DD/` for Athena
   (partition projection, no crawler).
3. The CloudWatch Logs lookup table `yuma_aia_register` is refreshed with `UpdateLookupTable` so A02 is register-aware
   (https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax-Lookup.html).
4. Metrics are published to `Yuma/AIA`: InventoryItems, NewlyDiscovered, PendingReview, ReviewsOverdue, RegisterIncomplete.

**Multi-account:** run per account and Region, or from a security account with a cross-account read role. That wiring
isn't in the draft.

**Runtime note:** bundle a current boto3. The Lambda runtime's copy may not include the AgentCore or Agent Registry
clients yet.

**ISM:** 2133, 2134, 2135. **Deployed by:** `deploy/cfn/yuma-aia-core.yaml`.

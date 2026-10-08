# PB5 Monthly ISM evidence export to S3

**Trigger:** EventBridge Scheduler at 07:00 Sydney time on the 1st of each month, or on demand
(`aws lambda invoke --function-name <stack>-pb5-evidence-export out.json`).

**Output:** `s3://<evidence bucket>/evidence/YYYY-MM-DD/`:
- `agent-register.csv`
- `ism-controls.csv`
- `summary.md`
- `manifest.json` (SHA-256 per file, logging posture, pack version)

The bucket is created with S3 Object Lock in compliance mode (default 2,555 days; set to the customer's records policy),
versioning, KMS encryption, Block Public Access and a TLS-only policy. Objects are written with SHA-256 checksums.

**Control status logic** (`pb5_evidence_export.py`):

| Control | How the status is set |
|---|---|
| ISM-2133 | Gap if any agent has no identity or two agents share one |
| ISM-2134 | Gap while discovered agents sit in PendingReview |
| ISM-2135 | Gap if owner/purpose, identities or tools/permissions are missing |
| ISM-2138 | Gap if approved agents are overdue or never reviewed |
| ISM-2158 | Evidence present only if guardrail data events are logged **and** GuardDuty AI Protection is enabled (`GetDetector` feature `AI_PROTECTION`) |
| ISM-2159 | Evidence present only if model invocation logging is on and the trail selects `AWS::BedrockAgentCore::Gateway` and `AWS::Bedrock::AgentAlias` data events |
| ISM-2136, 2137, 2139, 2140, 2156, 2157 | Attestation required, with the pack's supporting evidence named |

"No data" means the register is empty. The export supports an assessment; it is not a compliance determination.

**ISM:** 2134, 2135, 2138, 2159 plus the attested set. **Deployed by:** `deploy/cfn/yuma-aia-core.yaml`.

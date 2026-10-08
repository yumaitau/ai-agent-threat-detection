-- Yuma AIA-A06: Long-lived secrets created for AI workloads
--   (a) IAM user access keys created for users listed in the register or named like agents/bots/AI integrations
--   (b) AgentCore API key credential providers (static API keys held for an agent's outbound tool calls)
-- Pair with IAM Access Analyzer unused access findings (finding type UnusedIAMUserAccessKey) for keys that sit idle:
--   https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-findings.html
-- IAM events are recorded in us-east-1; AgentCore events in the region of the resource. Run once per region table.
WITH iam_keys AS (
  SELECT time_dt, accountid, 'CreateAccessKey' AS operation,
         actor.user.uid AS actor_arn,
         coalesce(json_extract_scalar(api.request.data, '$.userName'), actor.user.name) AS key_owner,
         json_extract_scalar(api.response.data, '$.accessKey.accessKeyId') AS access_key_id,
         src_endpoint.ip AS src_ip
  FROM "amazon_security_lake_glue_db_us_east_1"."amazon_security_lake_table_us_east_1_cloud_trail_mgmt_2_0"
  WHERE time_dt BETWEEN CURRENT_TIMESTAMP - INTERVAL '1' DAY AND CURRENT_TIMESTAMP
    AND api.service.name = 'iam.amazonaws.com'
    AND api.operation = 'CreateAccessKey'
    AND api.response.error IS NULL
),
agentcore_keys AS (
  SELECT time_dt, accountid, api.operation AS operation,
         actor.user.uid AS actor_arn,
         json_extract_scalar(api.request.data, '$.name') AS key_owner,
         CAST(NULL AS varchar) AS access_key_id,
         src_endpoint.ip AS src_ip
  FROM "amazon_security_lake_glue_db_ap_southeast_2"."amazon_security_lake_table_ap_southeast_2_cloud_trail_mgmt_2_0"
  WHERE time_dt BETWEEN CURRENT_TIMESTAMP - INTERVAL '1' DAY AND CURRENT_TIMESTAMP
    AND api.service.name = 'bedrock-agentcore.amazonaws.com'
    AND api.operation IN ('CreateApiKeyCredentialProvider', 'UpdateApiKeyCredentialProvider')
    AND api.response.error IS NULL
)
SELECT k.*, reg.agent_id, reg.agent_name, reg.owner
FROM (SELECT * FROM iam_keys UNION ALL SELECT * FROM agentcore_keys) k
LEFT JOIN yuma_aia.register_identities reg
  ON element_at(split(reg.identity_arn, '/'), -1) = k.key_owner
WHERE k.operation <> 'CreateAccessKey'
   OR reg.agent_id IS NOT NULL
   OR regexp_like(lower(coalesce(k.key_owner, '')), '(agent|bot|ai[-_]|llm|gpt|claude|bedrock|copilot|mcp|automation)')
ORDER BY k.time_dt DESC;

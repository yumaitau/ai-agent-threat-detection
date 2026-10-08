-- Yuma AIA-A04: Privilege added to an AI agent's IAM role (Bedrock agent service role, AgentCore runtime or gateway role,
-- or any role listed in the register's identities)
-- IAM is a global service; its CloudTrail events are recorded in us-east-1, so query that region's partition and
-- deploy the EventBridge rule (A04-*.eventbridge.json) in us-east-1.
--   https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html (Global service events)
-- The real-time path (EventBridge -> PB1) decides "is this an agent role" in Lambda with iam:GetRole (trust policy names
-- bedrock.amazonaws.com or bedrock-agentcore.amazonaws.com) plus the register. This SQL uses the register only.
WITH changes AS (
  SELECT time_dt,
         accountid,
         api.operation AS operation,
         actor.user.uid AS actor_arn,
         actor.session.issuer AS actor_role_arn,
         src_endpoint.ip AS src_ip,
         json_extract_scalar(api.request.data, '$.roleName') AS role_name,
         json_extract_scalar(api.request.data, '$.policyArn') AS policy_arn,
         json_extract_scalar(api.request.data, '$.policyName') AS inline_policy_name,
         json_extract_scalar(api.request.data, '$.policyDocument') AS policy_document
  FROM "amazon_security_lake_glue_db_us_east_1"."amazon_security_lake_table_us_east_1_cloud_trail_mgmt_2_0"
  WHERE time_dt BETWEEN CURRENT_TIMESTAMP - INTERVAL '1' DAY AND CURRENT_TIMESTAMP
    AND api.service.name = 'iam.amazonaws.com'
    AND api.operation IN ('AttachRolePolicy', 'PutRolePolicy', 'UpdateAssumeRolePolicy', 'PutRolePermissionsBoundary', 'DeleteRolePermissionsBoundary')
    AND api.response.error IS NULL
)
SELECT c.*,
       reg.agent_id, reg.agent_name, reg.owner,
       CASE
         WHEN regexp_like(coalesce(c.policy_arn, ''), ':policy/(AdministratorAccess|PowerUserAccess|IAMFullAccess|AmazonS3FullAccess|SecretsManagerReadWrite|AWSLambda_FullAccess|AmazonBedrockFullAccess)$') THEN 'High'
         WHEN regexp_like(coalesce(c.policy_document, ''), '"Action"\s*:\s*"\*"|"Action"\s*:\s*\[\s*"\*"|iam:PassRole|iam:\*|sts:AssumeRole') THEN 'High'
         WHEN c.operation IN ('UpdateAssumeRolePolicy', 'DeleteRolePermissionsBoundary') THEN 'High'
         ELSE 'Medium'
       END AS severity
FROM changes c
JOIN yuma_aia.register_identities reg
  -- match on account + final path segment so roles created with an IAM path (role/path/name) still join
  ON split_part(reg.identity_arn, ':', 5) = c.accountid
 AND element_at(split(reg.identity_arn, '/'), -1) = c.role_name
 AND reg.identity_arn LIKE 'arn:aws:iam::%:role/%'
ORDER BY c.time_dt DESC;

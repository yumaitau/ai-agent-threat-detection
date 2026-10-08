-- Yuma AIA-A10: Guardrail prompt-attack intervention, then data access by the same principal within 60 minutes
-- Detection of the injection itself is left to Bedrock Guardrails (PROMPT_ATTACK content filter) and GuardDuty
-- AI Protection (Impact:IAMUser/PromptInjection.Direct). This query adds the "and then what happened" step.
-- Needs CloudTrail Lake data events: AWS::Bedrock::Guardrail (ApplyGuardrail, includes evaluations made during
-- InvokeModel/Converse), AWS::S3::Object, AWS::Bedrock::KnowledgeBase, AWS::Bedrock::AgentAlias.
--   https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html
-- responseElements is map<string,string>; the nested assessments list is a JSON string, so a substring test is used
-- (the event has no per-assessment guardrail attribution, per the doc above).
--   https://docs.aws.amazon.com/awscloudtrail/latest/userguide/query-supported-event-schemas.html
-- Subqueries instead of WITH: AWS's published CloudTrail Lake samples only show subqueries. Replace $EDS_ID.
-- Threshold: 20 follow-up data calls (starting guess).
SELECT a.principal_key,
       min(a.attack_time) AS first_attack,
       count(DISTINCT a.attack_id) AS prompt_attacks,
       f.eventSource,
       f.eventName,
       count(DISTINCT f.followup_id) AS followup_calls,
       approx_distinct(f.target) AS distinct_targets,
       slice(array_agg(DISTINCT f.target), 1, 20) AS sample_targets,
       max(f.eventTime) AS last_followup
FROM (
  SELECT coalesce(userIdentity.sessionContext.sessionIssuer.arn, userIdentity.arn) AS principal_key,
         eventTime AS attack_time,
         eventID AS attack_id
  FROM $EDS_ID
  WHERE eventTime >= date_add('hour', -2, now())
    AND eventSource = 'bedrock.amazonaws.com'
    AND eventName = 'ApplyGuardrail'
    AND element_at(responseElements, 'action') = 'GUARDRAIL_INTERVENED'
    AND strpos(coalesce(element_at(responseElements, 'assessments'), ''), 'PROMPT_ATTACK') > 0
) a
JOIN (
  SELECT coalesce(userIdentity.sessionContext.sessionIssuer.arn, userIdentity.arn) AS principal_key,
         eventTime, eventSource, eventName, eventID AS followup_id,
         coalesce(element_at(requestParameters, 'bucketName') || '/' || element_at(requestParameters, 'key'),
                  element_at(requestParameters, 'knowledgeBaseId'),
                  element_at(requestParameters, 'agentId'),
                  element_at(requestParameters, 'secretId'),
                  element_at(requestParameters, 'name'),
                  element_at(resources, 1).arn) AS target
  FROM $EDS_ID
  WHERE eventTime >= date_add('hour', -3, now())
    AND errorCode IS NULL
    AND ((eventSource = 's3.amazonaws.com' AND eventName IN ('GetObject', 'ListObjects', 'ListObjectsV2'))
      OR (eventSource = 'bedrock.amazonaws.com' AND eventName IN ('Retrieve', 'RetrieveAndGenerate', 'InvokeAgent', 'InvokeInlineAgent', 'InvokeFlow'))
      OR (eventSource = 'bedrock-agentcore.amazonaws.com' AND eventName IN ('InvokeAgentRuntime', 'GetResourceOauth2Token', 'GetResourceApiKey'))
      OR (eventSource = 'secretsmanager.amazonaws.com' AND eventName = 'GetSecretValue')
      OR (eventSource = 'ssm.amazonaws.com' AND eventName IN ('GetParameter', 'GetParameters', 'GetParametersByPath')))
) f
  ON f.principal_key = a.principal_key
 AND f.eventTime > a.attack_time
 AND f.eventTime <= date_add('minute', 60, a.attack_time)
GROUP BY a.principal_key, f.eventSource, f.eventName
HAVING count(DISTINCT f.followup_id) >= 20
ORDER BY followup_calls DESC;

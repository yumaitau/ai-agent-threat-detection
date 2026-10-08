-- Yuma AIA-A03: New or changed AI agent, agent tool, gateway target, workload identity or credential provider
-- Real-time path: A03-agent-or-tool-change.eventbridge.json -> PB2 (register writer).
-- This CloudTrail Lake query is the backfill and weekly hunt. Replace $EDS_ID with the event data store ID.
-- These are management events (logged by default). Agent Registry event source "agent-registry.amazonaws.com" is
-- inferred from the service's signing name and is NOT verified; drop it if it never matches.
--   https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html
--   https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/understanding-gateway-cloudtrail-log-entries.html
SELECT
  eventTime,
  recipientAccountId,
  awsRegion,
  eventSource,
  eventName,
  userIdentity.arn AS actor_arn,
  userIdentity.sessionContext.sessionIssuer.arn AS actor_role_arn,
  sourceIPAddress,
  element_at(requestParameters, 'roleArn') AS agent_role_arn,
  element_at(requestParameters, 'agentResourceRoleArn') AS bedrock_agent_role_arn,
  element_at(requestParameters, 'name') AS resource_name,
  element_at(requestParameters, 'agentName') AS agent_name,
  element_at(requestParameters, 'authorizerType') AS authorizer_type,
  element_at(resources, 1).ARN AS resource_arn
FROM $EDS_ID
WHERE eventTime >= date_format(date_add('day', -7, now()), '%Y-%m-%d %H:%i:%s')
  AND errorCode IS NULL
  AND eventSource IN ('bedrock.amazonaws.com', 'bedrock-agentcore.amazonaws.com', 'agent-registry.amazonaws.com')
  AND eventName IN (
    'CreateAgent', 'UpdateAgent', 'CreateAgentActionGroup', 'UpdateAgentActionGroup',
    'CreateAgentAlias', 'UpdateAgentAlias', 'AssociateAgentKnowledgeBase', 'AssociateAgentCollaborator',
    'CreateKnowledgeBase', 'CreateDataSource', 'CreateFlow',
    'CreateAgentRuntime', 'UpdateAgentRuntime', 'CreateAgentRuntimeEndpoint',
    'CreateGateway', 'UpdateGateway', 'CreateGatewayTarget', 'UpdateGatewayTarget',
    'CreateWorkloadIdentity', 'UpdateWorkloadIdentity',
    'CreateOauth2CredentialProvider', 'UpdateOauth2CredentialProvider',
    'CreateApiKeyCredentialProvider', 'UpdateApiKeyCredentialProvider',
    'CreateMemory', 'CreateBrowser', 'CreateCodeInterpreter', 'CreateHarness',
    'CreateRegistryRecord', 'UpdateRegistryRecord', 'UpdateRegistryRecordStatus')
ORDER BY eventTime DESC;

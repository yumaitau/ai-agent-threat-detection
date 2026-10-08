-- Yuma AIA-A11: AgentCore Gateway (MCP) tool-call anomalies per caller
--   - tool-call burst (>= 100 tools/call in 10 minutes from one JWT subject)
--   - breadth (>= 15 distinct tools in 10 minutes)
--   - auth failure burst (>= 20 HTTP 401/403 responses in 10 minutes from one source IP)
--   - sensitive tool names (delete, drop, write, send, transfer, exec, admin, secret) called by a subject for the first time
-- Needs InvokeGateway data events (advanced selector resources.type = AWS::BedrockAgentCore::Gateway).
-- Gateway callers are identified by JWT claims in additionalEventData, not by IAM identity; errors are in
-- responseElements (statusCode, body), not errorCode.
--   https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/understanding-gateway-cloudtrail-log-entries.html
--   https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/enabling-cloudtrail-data-event-logging.html
-- Nested JSON in map values is read with json_extract_scalar(element_at(...)). Replace $EDS_ID.
SELECT gateway_arn, caller_sub, src_ip, window_start,
       count_if(method = 'tools/call') AS tool_calls,
       count(DISTINCT tool_name) AS distinct_tools,
       count_if(status_code IN ('401', '403')) AS auth_failures,
       count_if(regexp_like(lower(coalesce(tool_name, '')), '(delete|drop|remove|write|put|update|send|transfer|exec|run|admin|secret|credential|payment)')) AS sensitive_calls,
       slice(array_agg(DISTINCT tool_name), 1, 25) AS tools
FROM (
  SELECT element_at(resources, 1).arn AS gateway_arn,
         json_extract_scalar(element_at(additionalEventData, 'jwt'), '$.claims.sub') AS caller_sub,
         sourceIPAddress AS src_ip,
         date_trunc('hour', eventTime) + (minute(eventTime) / 10) * INTERVAL '10' MINUTE AS window_start,
         json_extract_scalar(element_at(requestParameters, 'body'), '$.method') AS method,
         json_extract_scalar(element_at(requestParameters, 'body'), '$.params.name') AS tool_name,
         element_at(responseElements, 'statusCode') AS status_code
  FROM $EDS_ID
  WHERE eventTime >= date_add('hour', -1, now())
    AND eventSource = 'bedrock-agentcore.amazonaws.com'
    AND eventName = 'InvokeGateway'
) g
GROUP BY gateway_arn, caller_sub, src_ip, window_start
HAVING count_if(method = 'tools/call') >= 100
    OR count(DISTINCT tool_name) >= 15
    OR count_if(status_code IN ('401', '403')) >= 20
    OR count_if(regexp_like(lower(coalesce(tool_name, '')), '(delete|drop|remove|write|put|update|send|transfer|exec|run|admin|secret|credential|payment)')) >= 1
ORDER BY tool_calls DESC;

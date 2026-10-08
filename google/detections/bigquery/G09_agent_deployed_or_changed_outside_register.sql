-- YUMA-GAI-G09  Agent Runtime (Reasoning Engine) or Gemini Enterprise agent created/changed and not in the register
-- Status: HUNT (parsed offline). Method names are from the aiplatform v1 ReasoningEngineService proto; they are not on the
--   audited-operations page, so confirm them in a lab. Discovery Engine names are matched loosely.
--   https://docs.cloud.google.com/vertex-ai/docs/general/audit-logging
-- Maps: ISM-2134, ISM-2135, ISM-2133 | ATT&CK T1578 | ATLAS AML.T0081 | OWASP ASI04, ASI10
WITH changes AS (
  SELECT
    l.timestamp AS event_time,
    l.proto_payload.audit_log.service_name AS service_name,
    l.proto_payload.audit_log.method_name AS method_name,
    l.proto_payload.audit_log.resource_name AS resource_name,
    l.proto_payload.audit_log.authentication_info.principal_email AS actor,
    REGEXP_EXTRACT(l.log_name, r'^projects/([^/]+)/') AS project_id
  FROM `${logs_table}` AS l
  WHERE l.timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 25 HOUR)
    AND l.log_id = 'cloudaudit.googleapis.com/activity'
    AND l.proto_payload.audit_log.service_name IN ('aiplatform.googleapis.com', 'discoveryengine.googleapis.com')
    AND REGEXP_CONTAINS(l.proto_payload.audit_log.method_name,
        r'(?i)(ReasoningEngineService\.(Create|Update)ReasoningEngine|\.(CreateAgent|UpdateAgent|CreateEngine|CreateAssistant|UpdateAssistant)$)')
)
SELECT
  'MEDIUM' AS severity,
  c.resource_name AS entity,
  CONCAT(c.actor, ' ran ', c.method_name, ' on ', c.resource_name, ' (not in register)') AS summary,
  c.*
FROM changes AS c
LEFT JOIN `${register_dataset}.v_register_current` AS r
  ON STARTS_WITH(c.resource_name, r.agent_key) OR STARTS_WITH(r.agent_key, c.resource_name)
WHERE r.agent_key IS NULL

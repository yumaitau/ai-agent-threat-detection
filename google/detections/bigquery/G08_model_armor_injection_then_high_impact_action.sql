-- YUMA-GAI-G08  Model Armor prompt-injection / jailbreak match, then a high-impact action in the same project within 2 hours
-- Status: RULE-GRADE (parsed offline). Reference implementation for the SecOps draft.
-- Sources (Log Analytics _AllLogs):
--   Model Armor sanitize logs: log_id 'modelarmor.googleapis.com/sanitize_operations',
--     json_payload.sanitizationResult.filterResults.pi_and_jailbreak.piAndJailbreakFilterResult.matchState = 'MATCH_FOUND',
--     labels 'modelarmor.googleapis.com/client_name' and '.../client_correlation_id'. Needs log_sanitize_operations on the template
--     or floor setting. https://docs.cloud.google.com/model-armor/configure-logging
--     https://docs.cloud.google.com/model-armor/reference/rest/v1/SanitizationResult
--   Follow-on actions: Admin Activity + Data Access audit logs (BigQuery InsertJob and IAM Credentials calls are Data Access
--     or Admin depending on service; enable DATA_READ/DATA_WRITE for iamcredentials and bigquery to see them).
-- Project join key: project parsed from log_name (projects/<id>/logs/...) on both sides.
-- UNVALIDATED: whether sanitizationResult is nested under json_payload exactly as in the REST type (the Model Armor logging page
--   shows it as jsonPayload.sanitizationResult); 'labels' key access syntax on the Log Analytics labels JSON column.
-- Maps: ISM-2158, ISM-1924, ISM-2113 | ATT&CK T1567, T1098 | ATLAS AML.T0051.001, AML.T0054, AML.T0086 | OWASP LLM01, ASI01, ASI02
WITH params AS (
  SELECT
    3 AS lookback_hours,
    120 AS window_minutes,
    r'(?i)(SetIamPolicy$|CreateServiceAccountKey|GenerateAccessToken|SignJwt|SignBlob|JobService\.InsertJob|UpdateReasoningEngine|storage\.setIamPermissions)' AS follow_on_re
),
injections AS (
  SELECT
    l.timestamp AS ma_time,
    REGEXP_EXTRACT(l.log_name, r'^projects/([^/]+)/') AS project_id,
    JSON_VALUE(l.labels, '$."modelarmor.googleapis.com/client_name"') AS ma_client,
    JSON_VALUE(l.labels, '$."modelarmor.googleapis.com/client_correlation_id"') AS ma_correlation_id,
    JSON_VALUE(l.json_payload.sanitizationResult.filterMatchState) AS overall_match
  FROM `${logs_table}` AS l
  CROSS JOIN params AS p
  WHERE l.timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL p.lookback_hours HOUR)
    AND l.log_id = 'modelarmor.googleapis.com/sanitize_operations'
    AND JSON_VALUE(l.json_payload.sanitizationResult.filterResults.pi_and_jailbreak.piAndJailbreakFilterResult.matchState) = 'MATCH_FOUND'
),
actions AS (
  SELECT
    l.timestamp AS action_time,
    REGEXP_EXTRACT(l.log_name, r'^projects/([^/]+)/') AS project_id,
    l.proto_payload.audit_log.method_name AS method_name,
    l.proto_payload.audit_log.authentication_info.principal_email AS actor,
    l.proto_payload.audit_log.resource_name AS resource_name,
    l.proto_payload.audit_log.request_metadata.caller_ip AS caller_ip
  FROM `${logs_table}` AS l
  CROSS JOIN params AS p
  WHERE l.timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL p.lookback_hours HOUR)
    AND l.log_id IN ('cloudaudit.googleapis.com/activity', 'cloudaudit.googleapis.com/data_access')
    AND REGEXP_CONTAINS(l.proto_payload.audit_log.method_name, p.follow_on_re)
    AND (l.proto_payload.audit_log.status IS NULL OR l.proto_payload.audit_log.status.code IS NULL
         OR l.proto_payload.audit_log.status.code = 0)
)
SELECT
  'HIGH' AS severity,
  i.project_id AS entity,
  CONCAT('Model Armor injection match (', IFNULL(i.ma_client, 'unknown client'), ') then ', a.method_name, ' by ', IFNULL(a.actor, '?'),
         ' ', CAST(TIMESTAMP_DIFF(a.action_time, i.ma_time, MINUTE) AS STRING), ' min later') AS summary,
  i.project_id,
  i.ma_time,
  i.ma_client,
  i.ma_correlation_id,
  a.action_time,
  a.method_name,
  a.actor,
  a.resource_name,
  a.caller_ip
FROM injections AS i
CROSS JOIN params AS p
JOIN actions AS a
  ON a.project_id = i.project_id
 AND a.action_time BETWEEN i.ma_time AND TIMESTAMP_ADD(i.ma_time, INTERVAL p.window_minutes MINUTE)
QUALIFY ROW_NUMBER() OVER (PARTITION BY i.project_id, a.method_name, a.resource_name ORDER BY i.ma_time) = 1

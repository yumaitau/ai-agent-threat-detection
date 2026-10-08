-- YUMA-GAI-G07  User-managed key created or uploaded for an AI agent service account
-- Status: RULE-GRADE (parsed offline). Field paths follow CSA 2.30 (Log Analytics _AllLogs).
--   https://github.com/GoogleCloudPlatform/security-analytics/blob/main/backends/log_analytics/sql/2_30_service_accounts_or_keys_created_by_non_approved_identity.sql
-- Methods: google.iam.admin.v1.CreateServiceAccountKey / UploadServiceAccountKey (as in Google's community SecOps rule).
-- resource_name on these events is projects/-/serviceAccounts/<unique-id-or-email>; the register view lists both.
-- Maps: ISM-2141, ISM-2142, ISM-2146, ISM-2143 | ATT&CK T1098.001 | ATLAS AML.T0012, AML.T0083 | OWASP ASI03
WITH params AS (
  SELECT
    70 AS lookback_minutes,
    r'(?i)(agent|\bai\b|-ai-|llm|gemini|vertex|mcp|bot|assistant|reasoning)' AS ai_name_re
),
keys AS (
  SELECT
    l.timestamp AS event_time,
    l.proto_payload.audit_log.method_name AS method_name,
    l.proto_payload.audit_log.authentication_info.principal_email AS created_by,
    l.proto_payload.audit_log.request_metadata.caller_ip AS caller_ip,
    l.proto_payload.audit_log.resource_name AS resource_name,
    REGEXP_EXTRACT(l.proto_payload.audit_log.resource_name, r'serviceAccounts/([^/]+)') AS sa_ref,
    JSON_VALUE(l.proto_payload.audit_log.response.name) AS key_name,
    JSON_VALUE(l.resource.labels.project_id) AS project_id
  FROM `${logs_table}` AS l
  CROSS JOIN params AS p
  WHERE l.timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL p.lookback_minutes MINUTE)
    AND l.log_id = 'cloudaudit.googleapis.com/activity'
    AND l.proto_payload.audit_log.method_name IN (
      'google.iam.admin.v1.CreateServiceAccountKey',
      'google.iam.admin.v1.UploadServiceAccountKey')
    AND (l.proto_payload.audit_log.status IS NULL OR l.proto_payload.audit_log.status.code IS NULL
         OR l.proto_payload.audit_log.status.code = 0)
)
SELECT
  'HIGH' AS severity,
  k.sa_ref AS entity,
  CONCAT(k.created_by, ' created a user-managed key for AI service account ', k.sa_ref) AS summary,
  k.event_time,
  k.method_name,
  k.created_by,
  k.caller_ip,
  k.sa_ref,
  k.key_name,
  k.project_id,
  r.agent_key AS register_agent_key
FROM keys AS k
CROSS JOIN params AS p
LEFT JOIN `${register_dataset}.v_ai_service_accounts` AS r
  ON LOWER(k.sa_ref) IN (LOWER(r.service_account_email), LOWER(r.service_account_unique_id))
WHERE r.agent_key IS NOT NULL
   OR REGEXP_CONTAINS(k.sa_ref, p.ai_name_re)

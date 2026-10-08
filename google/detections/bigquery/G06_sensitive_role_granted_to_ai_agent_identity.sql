-- YUMA-GAI-G06  Sensitive IAM role granted to an AI agent identity, an AI service agent or a registered AI service account
-- Status: RULE-GRADE (parsed offline; field paths copied from Google's CSA queries 2.20-2.22, Apache-2.0)
-- Source: Cloud Logging Log Analytics view `_AllLogs` (Admin Activity audit logs, org-level aggregated sink recommended).
--   https://github.com/GoogleCloudPlatform/security-analytics/tree/main/backends/log_analytics/sql
-- Agent identity principals: principal://agents.global.org-ORG_ID.system.id.goog/... https://docs.cloud.google.com/iam/docs/auth-agent-own-identity
-- Register: ${register_dataset}.v_ai_service_accounts (service accounts / identities recorded for AI agents)
-- Maps: ISM-2156, ISM-2133, ISM-2157 | E8 restrict administrative privileges | ATT&CK T1098.003 | ATLAS AML.T0081, AML.T0108 | OWASP LLM06, ASI03
WITH params AS (
  SELECT
    70 AS lookback_minutes,
    r'(?i)(agents\.global\.|gcp-sa-aiplatform-re\.|gcp-sa-aiplatform\.|gcp-sa-discoveryengine\.)' AS ai_member_re,
    r'(?i)^roles/(owner|editor|iam\.serviceAccountTokenCreator|iam\.serviceAccountUser|iam\.serviceAccountKeyAdmin|iam\.serviceAccountAdmin|iam\.workloadIdentityUser|iam\.securityAdmin|resourcemanager\..*|storage\.admin|bigquery\.(admin|dataOwner|dataEditor)|secretmanager\.(admin|secretAccessor)|cloudkms\..*|compute\.admin|aiplatform\.admin|discoveryengine\.admin|run\.admin|cloudfunctions\.admin)$' AS sensitive_role_re
),
deltas AS (
  SELECT
    l.timestamp AS event_time,
    l.proto_payload.audit_log.authentication_info.principal_email AS grantor,
    l.proto_payload.audit_log.request_metadata.caller_ip AS caller_ip,
    l.proto_payload.audit_log.resource_name AS resource_name,
    l.proto_payload.audit_log.method_name AS method_name,
    l.resource.type AS resource_type,
    JSON_VALUE(bd.member) AS grantee,
    JSON_VALUE(bd.role) AS role,
    JSON_VALUE(bd.action) AS action
  FROM `${logs_table}` AS l
  CROSS JOIN UNNEST(JSON_QUERY_ARRAY(l.proto_payload.audit_log.service_data.policyDelta.bindingDeltas)) AS bd
  CROSS JOIN params AS p
  WHERE l.timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL p.lookback_minutes MINUTE)
    AND l.log_id = 'cloudaudit.googleapis.com/activity'
    AND LOWER(l.proto_payload.audit_log.method_name) LIKE '%setiampolicy'
)
SELECT
  IF(REGEXP_CONTAINS(d.role, r'(?i)roles/(owner|editor|iam\.serviceAccountTokenCreator)'), 'HIGH', 'MEDIUM') AS severity,
  d.grantee AS entity,
  CONCAT(d.grantor, ' granted ', d.role, ' to AI identity ', d.grantee, ' on ', d.resource_name) AS summary,
  d.event_time,
  d.grantor,
  d.grantee,
  d.role,
  d.resource_type,
  d.resource_name,
  d.caller_ip,
  r.agent_key AS register_agent_key
FROM deltas AS d
CROSS JOIN params AS p
LEFT JOIN `${register_dataset}.v_ai_service_accounts` AS r
  ON LOWER(d.grantee) = LOWER(r.member)
WHERE d.action = 'ADD'
  AND REGEXP_CONTAINS(d.role, p.sensitive_role_re)
  AND (REGEXP_CONTAINS(d.grantee, p.ai_member_re) OR r.member IS NOT NULL)

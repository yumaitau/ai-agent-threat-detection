-- YUMA-GAI-G15  AI agent service account using a user-managed key from a public (non-Google-internal) IP
-- Status: HUNT (parsed offline). AuditLog.authenticationInfo.serviceAccountKeyName is set when a key authenticated the call.
--   https://docs.cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog
-- Caveat: caller_ip is 'private' or 'gce-internal-ip' for calls from inside Google Cloud, so a public IP means outside, or
--   via a NAT/proxy. Add your known egress ranges to the exclusion.
-- Maps: ISM-2141, ISM-2144, ISM-2136 | ATT&CK T1078.004 | ATLAS AML.T0012, AML.T0055 | OWASP ASI03
WITH u AS (
  SELECT
    l.timestamp,
    l.proto_payload.audit_log.authentication_info.principal_email AS sa_email,
    l.proto_payload.audit_log.authentication_info.service_account_key_name AS key_name,
    l.proto_payload.audit_log.request_metadata.caller_ip AS caller_ip,
    l.proto_payload.audit_log.method_name AS method_name
  FROM `${logs_table}` AS l
  WHERE l.timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 DAY)
    AND l.proto_payload.audit_log.authentication_info.service_account_key_name IS NOT NULL
    AND l.proto_payload.audit_log.request_metadata.caller_ip NOT IN ('private', 'gce-internal-ip')
)
SELECT
  'HIGH' AS severity,
  u.sa_email AS entity,
  CONCAT(u.sa_email, ' used key auth from ', STRING_AGG(DISTINCT u.caller_ip, ', ')) AS summary,
  u.sa_email,
  ARRAY_AGG(DISTINCT u.key_name) AS keys,
  ARRAY_AGG(DISTINCT u.caller_ip) AS caller_ips,
  ARRAY_AGG(DISTINCT u.method_name LIMIT 20) AS methods,
  COUNT(*) AS calls
FROM u
JOIN `${register_dataset}.v_ai_service_accounts` AS r
  ON LOWER(r.service_account_email) = LOWER(u.sa_email)
GROUP BY u.sa_email

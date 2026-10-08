-- YUMA-GAI-G02  Domain-wide delegation granted (AUTHORIZE_API_CLIENT_ACCESS)
-- Status: HUNT (parsed offline). Event name verified in the Reports API admin domain-settings reference; the export columns
--   holding API_CLIENT_NAME / API_SCOPES are NOT confirmed, so the query returns the whole admin struct for triage.
--   https://developers.google.com/workspace/admin/reports/v1/appendix/activity/admin-domain-settings
-- Alternative with no export: Reports API activities.list(applicationName=admin, eventName=AUTHORIZE_API_CLIENT_ACCESS).
-- Maps: ISM-2137, ISM-2133, ISM-2156, ISM-2157 | ATT&CK T1098.001, T1550.001 | ATLAS AML.T0012 | OWASP ASI03, LLM06
SELECT
  'HIGH' AS severity,
  a.email AS entity,
  CONCAT(a.email, ' authorised domain-wide delegation for an API client') AS summary,
  TIMESTAMP_MICROS(a.time_usec) AS event_time,
  a.email AS admin_email,
  a.ip_address,
  a.event_name,
  TO_JSON_STRING(a.admin) AS admin_details
FROM `${workspace_activity_table}` AS a
WHERE a._PARTITIONTIME >= TIMESTAMP_SUB(TIMESTAMP_TRUNC(CURRENT_TIMESTAMP(), DAY), INTERVAL 1 DAY)
  AND a.record_type = 'admin'
  AND a.event_name IN ('AUTHORIZE_API_CLIENT_ACCESS', 'TOGGLE_OAUTH_ACCESS_TO_ALL_APIS')

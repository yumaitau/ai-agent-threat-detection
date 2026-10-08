-- YUMA-GAI-G05  Gemini in Workspace usage by users outside the approved list (ISM-2074 usage policy evidence)
-- Status: HUNT, UNVALIDATED SOURCE. The export says it carries "any updates to the Reports API", but a record_type value for
--   gemini_in_workspace_apps is not documented. If it is absent, pull Reports API activities.list(applicationName=gemini_in_workspace_apps,
--   eventName=feature_utilization) into a table instead (180 days history, from 20 Jun 2025).
--   https://developers.google.com/workspace/admin/reports/v1/appendix/activity/gemini-in-workspace-apps
-- Register: ${register_dataset}.gemini_approved_users (email STRING)
-- Maps: ISM-2074, ISM-2134 | ATLAS n/a (governance) | OWASP LLM02
SELECT
  'LOW' AS severity,
  a.email AS entity,
  CONCAT(a.email, ' used Gemini in Workspace ', CAST(COUNT(*) AS STRING), ' times in 7 days and is not on the approved list') AS summary,
  a.email,
  COUNT(*) AS uses,
  MIN(TIMESTAMP_MICROS(a.time_usec)) AS first_seen,
  MAX(TIMESTAMP_MICROS(a.time_usec)) AS last_seen
FROM `${workspace_activity_table}` AS a
LEFT JOIN `${register_dataset}.gemini_approved_users` AS ok
  ON LOWER(ok.email) = LOWER(a.email)
WHERE a._PARTITIONTIME >= TIMESTAMP_SUB(TIMESTAMP_TRUNC(CURRENT_TIMESTAMP(), DAY), INTERVAL 7 DAY)
  AND a.record_type = 'gemini_in_workspace_apps'
  AND a.event_name = 'feature_utilization'
  AND ok.email IS NULL
GROUP BY a.email

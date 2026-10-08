-- YUMA-GAI-G01  AI or agent OAuth app granted sensitive Google Workspace scopes, not in the approved register
-- Status: RULE-GRADE (parsed offline with sqlglot, BigQuery dialect; not run against live data)
-- Source: Google Workspace BigQuery export, table `activity` (record_type 'token', event_name 'authorize').
--   Columns used (token.client_id, token.app_name, UNNEST(token.scope), time_usec, email, ip_address, _PARTITIONTIME)
--   follow Google's example queries: https://support.google.com/a/answer/9079965
--   Event meaning: https://developers.google.com/workspace/admin/reports/v1/appendix/activity/token
-- Register: ${register_dataset}.approved_apps (loaded from register/approved_apps.csv; PB2 appends approvals)
-- Schedule: hourly (deploy/terraform scheduled query). Output columns are standard: severity, entity, summary + details.
-- Maps: ISM-2137, ISM-2138, ISM-2139, ISM-2156 | ATT&CK T1528 | ATLAS AML.T0012 | OWASP LLM06, ASI03
-- UNVALIDATED: literal values record_type = 'token' and event_name = 'authorize' in the export (taken from the Reports API names).
WITH params AS (
  SELECT
    2 AS lookback_hours,
    r'(?i)(openai|chatgpt|anthropic|claude|copilot|gemini|perplexity|deepseek|mistral|grok|otter|fireflies|notetaker|zapier|n8n|make\.com|langchain|cursor|\bai\b|gpt|llm|mcp|agent|assistant|\bbot\b)' AS ai_name_re,
    r'(?i)(mail\.google\.com/|/auth/(gmail|drive|calendar|contacts|admin\.|cloud-platform|script\.|chat\.|documents|spreadsheets|presentations|directory|apps\.|tasks))' AS sensitive_scope_re
),
grants AS (
  SELECT
    TIMESTAMP_MICROS(a.time_usec) AS event_time,
    a.email AS user_email,
    a.ip_address,
    a.token.client_id AS client_id,
    a.token.app_name AS app_name,
    scope
  FROM `${workspace_activity_table}` AS a
  LEFT JOIN UNNEST(a.token.scope) AS scope
  CROSS JOIN params AS p
  WHERE a._PARTITIONTIME >= TIMESTAMP_SUB(TIMESTAMP_TRUNC(CURRENT_TIMESTAMP(), DAY), INTERVAL 1 DAY)
    AND a.record_type = 'token'
    AND a.event_name = 'authorize'
    AND TIMESTAMP_MICROS(a.time_usec) >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL p.lookback_hours HOUR)
),
flagged AS (
  SELECT g.*
  FROM grants AS g
  CROSS JOIN params AS p
  LEFT JOIN `${register_dataset}.approved_apps` AS ok
    ON ok.oauth_client_id = g.client_id
  WHERE ok.oauth_client_id IS NULL
    AND REGEXP_CONTAINS(IFNULL(g.scope, ''), p.sensitive_scope_re)
    AND REGEXP_CONTAINS(IFNULL(g.app_name, ''), p.ai_name_re)
)
SELECT
  IF(COUNTIF(REGEXP_CONTAINS(scope, r'(?i)(mail\.google\.com/|/auth/(gmail|admin\.|cloud-platform))')) > 0, 'HIGH', 'MEDIUM') AS severity,
  CONCAT('oauth:', client_id) AS entity,
  CONCAT(ANY_VALUE(app_name), ' granted ', CAST(COUNT(DISTINCT scope) AS STRING), ' sensitive scope(s) by ',
         CAST(COUNT(DISTINCT user_email) AS STRING), ' user(s)') AS summary,
  client_id,
  ANY_VALUE(app_name) AS app_name,
  MIN(event_time) AS first_seen,
  MAX(event_time) AS last_seen,
  ARRAY_AGG(DISTINCT user_email IGNORE NULLS) AS granting_users,
  ARRAY_AGG(DISTINCT scope IGNORE NULLS) AS scopes,
  ARRAY_AGG(DISTINCT ip_address IGNORE NULLS) AS source_ips
FROM flagged
GROUP BY client_id

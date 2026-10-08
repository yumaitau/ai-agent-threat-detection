-- YUMA-GAI-G04  AI or agent OAuth app (or any unapproved app) pulling Workspace data far above its own 14-day baseline
-- Status: RULE-GRADE on event counts and distinct users (columns verified). Byte volume is an optional extra (see below).
-- Source: Workspace BigQuery export `activity`, record_type 'token', event_name 'activity' (OAuth API calls by apps).
--   https://developers.google.com/workspace/admin/reports/v1/appendix/activity/token
--   https://support.google.com/a/answer/9079965
-- Logic: per app per hour, calls and distinct users; alert when the last full hour is above the app's 14-day hourly p95
--   multiplied by a factor AND above an absolute floor (so tiny apps don't page anyone). Apps never seen before are
--   alerted if they cross the floor.
-- UNVALIDATED: token.num_response_bytes and token.product_bucket as export columns. If present, uncomment the lines marked [bytes].
-- Maps: ISM-2157, ISM-2159 | ATT&CK T1114.002, T1530 | ATLAS AML.T0085.001, AML.T0086, AML.T0036 | OWASP LLM06, LLM02, ASI02, ASI10
WITH params AS (
  SELECT
    14 AS baseline_days,
    3.0 AS factor,
    2000 AS min_calls,
    10 AS min_users,
    r'(?i)(openai|chatgpt|anthropic|claude|copilot|gemini|perplexity|deepseek|mistral|grok|otter|fireflies|notetaker|zapier|n8n|make\.com|langchain|cursor|\bai\b|gpt|llm|mcp|agent|assistant|\bbot\b)' AS ai_name_re
),
hourly AS (
  SELECT
    TIMESTAMP_TRUNC(TIMESTAMP_MICROS(a.time_usec), HOUR) AS hour,
    a.token.client_id AS client_id,
    ANY_VALUE(a.token.app_name) AS app_name,
    COUNT(*) AS calls,
    COUNT(DISTINCT a.email) AS users
    -- [bytes] , SUM(a.token.num_response_bytes) AS response_bytes
  FROM `${workspace_activity_table}` AS a
  CROSS JOIN params AS p
  WHERE a._PARTITIONTIME >= TIMESTAMP_SUB(TIMESTAMP_TRUNC(CURRENT_TIMESTAMP(), DAY), INTERVAL p.baseline_days + 1 DAY)
    AND a.record_type = 'token'
    AND a.event_name = 'activity'
  GROUP BY hour, client_id
),
baseline AS (
  SELECT
    client_id,
    APPROX_QUANTILES(calls, 100)[OFFSET(95)] AS p95_calls,
    APPROX_QUANTILES(users, 100)[OFFSET(95)] AS p95_users
  FROM hourly
  WHERE hour < TIMESTAMP_SUB(TIMESTAMP_TRUNC(CURRENT_TIMESTAMP(), HOUR), INTERVAL 1 HOUR)
  GROUP BY client_id
),
latest AS (
  SELECT *
  FROM hourly
  WHERE hour = TIMESTAMP_SUB(TIMESTAMP_TRUNC(CURRENT_TIMESTAMP(), HOUR), INTERVAL 1 HOUR)
)
SELECT
  IF(l.calls >= 5 * IFNULL(b.p95_calls, 0) AND l.users >= p.min_users, 'HIGH', 'MEDIUM') AS severity,
  CONCAT('oauth:', l.client_id) AS entity,
  CONCAT(IFNULL(l.app_name, l.client_id), ': ', CAST(l.calls AS STRING), ' API calls across ', CAST(l.users AS STRING),
         ' users in one hour (14d p95 ', CAST(IFNULL(b.p95_calls, 0) AS STRING), ')') AS summary,
  l.client_id,
  l.app_name,
  l.hour,
  l.calls,
  l.users,
  b.p95_calls,
  b.p95_users,
  ok.oauth_client_id IS NOT NULL AS in_register
FROM latest AS l
CROSS JOIN params AS p
LEFT JOIN baseline AS b USING (client_id)
LEFT JOIN `${register_dataset}.approved_apps` AS ok
  ON ok.oauth_client_id = l.client_id
WHERE (REGEXP_CONTAINS(IFNULL(l.app_name, ''), p.ai_name_re) OR ok.oauth_client_id IS NULL)
  AND (
    (l.calls >= p.min_calls AND l.calls > p.factor * IFNULL(b.p95_calls, 0))
    OR (l.users >= p.min_users AND l.users > p.factor * IFNULL(b.p95_users, 0))
  )

-- YUMA-GAI-G10  Model invocation by a new principal or far above that principal's baseline (cost harvesting / LLMjacking)
-- Status: HUNT (parsed offline). Builds on Google's CSA 4.30/4.31 LLM usage queries (method parsing copied).
--   Needs Data Access audit logs for aiplatform.googleapis.com (off by default).
--   https://github.com/GoogleCloudPlatform/security-analytics/blob/main/backends/log_analytics/sql/4_30_top_llm_users_by_model.sql
-- Maps: ISM-2159, ISM-2136 | ATT&CK T1496 | ATLAS AML.T0034, AML.T0040 | OWASP LLM10
WITH calls AS (
  SELECT
    TIMESTAMP_TRUNC(l.timestamp, HOUR) AS hour,
    l.proto_payload.audit_log.authentication_info.principal_email AS principal,
    l.proto_payload.audit_log.request_metadata.caller_ip AS caller_ip,
    SUBSTR(l.proto_payload.audit_log.resource_name, STRPOS(l.proto_payload.audit_log.resource_name, 'publishers/') + 11) AS model_name
  FROM `${logs_table}` AS l
  WHERE l.timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 15 DAY)
    AND l.proto_payload.audit_log.service_name = 'aiplatform.googleapis.com'
    AND SPLIT(l.proto_payload.audit_log.method_name, '.')[SAFE_OFFSET(5)] IN ('Predict', 'RawPredict', 'GenerateContent', 'StreamGenerateContent')
),
hourly AS (
  SELECT hour, principal, COUNT(*) AS n, ARRAY_AGG(DISTINCT caller_ip IGNORE NULLS LIMIT 10) AS ips,
         ARRAY_AGG(DISTINCT model_name IGNORE NULLS LIMIT 10) AS models
  FROM calls GROUP BY hour, principal
),
base AS (
  SELECT principal, APPROX_QUANTILES(n, 100)[OFFSET(95)] AS p95, MIN(hour) AS first_hour
  FROM hourly WHERE hour < TIMESTAMP_SUB(TIMESTAMP_TRUNC(CURRENT_TIMESTAMP(), HOUR), INTERVAL 1 HOUR)
  GROUP BY principal
)
SELECT
  IF(b.principal IS NULL, 'MEDIUM', 'LOW') AS severity,
  h.principal AS entity,
  CONCAT(h.principal, ': ', CAST(h.n AS STRING), ' model calls last hour',
         IF(b.principal IS NULL, ' (new principal)', CONCAT(' vs p95 ', CAST(b.p95 AS STRING)))) AS summary,
  h.*, b.p95
FROM hourly AS h
LEFT JOIN base AS b USING (principal)
WHERE h.hour = TIMESTAMP_SUB(TIMESTAMP_TRUNC(CURRENT_TIMESTAMP(), HOUR), INTERVAL 1 HOUR)
  AND (b.principal IS NULL OR (h.n > 200 AND h.n > 5 * b.p95))

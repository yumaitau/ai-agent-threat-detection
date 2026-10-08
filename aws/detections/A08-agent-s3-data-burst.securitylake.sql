-- Yuma AIA-A08: AI agent role reading an unusual volume of S3 objects (excessive agency or exfiltration via tools)
-- S3 data events are a native Security Lake source (s3_data_2_0) when the trail logs them.
-- Threshold: 5x the role's 14-day hourly p95 and at least 200 GetObject calls in the hour (starting guess; tune).
WITH agent_roles AS (
  SELECT identity_arn, agent_id, agent_name, owner FROM yuma_aia.register_identities
  WHERE identity_arn LIKE 'arn:aws:iam::%:role/%'
),
hourly AS (
  SELECT date_trunc('hour', time_dt) AS hr,
         actor.session.issuer AS role_arn,
         count(*) AS gets,
         count(DISTINCT json_extract_scalar(api.request.data, '$.bucketName')) AS buckets
  FROM "amazon_security_lake_glue_db_ap_southeast_2"."amazon_security_lake_table_ap_southeast_2_s3_data_2_0"
  WHERE time_dt BETWEEN CURRENT_TIMESTAMP - INTERVAL '14' DAY AND CURRENT_TIMESTAMP
    AND api.service.name = 's3.amazonaws.com'
    AND api.operation = 'GetObject'
    AND actor.session.issuer IN (SELECT identity_arn FROM agent_roles)
  GROUP BY 1, 2
),
base AS (
  SELECT role_arn, approx_percentile(gets, 0.95) AS p95_gets
  FROM hourly WHERE hr < date_trunc('hour', CURRENT_TIMESTAMP) GROUP BY role_arn
)
SELECT h.hr, h.role_arn, r.agent_id, r.agent_name, r.owner, h.gets, h.buckets, b.p95_gets
FROM hourly h
JOIN agent_roles r ON r.identity_arn = h.role_arn
LEFT JOIN base b ON b.role_arn = h.role_arn
WHERE h.hr >= date_trunc('hour', CURRENT_TIMESTAMP - INTERVAL '1' HOUR)
  AND h.gets >= 200
  AND (b.p95_gets IS NULL OR h.gets > 5 * b.p95_gets)
ORDER BY h.gets DESC;

-- Yuma AIA-A01: Shadow AI - workloads resolving third-party AI model API domains (Security Lake, OCSF)
-- Table: Route 53 resolver query logs source, version 2 (route53_2_0). Replace <region> e.g. ap_southeast_2.
-- Field names query.hostname, query.type, src_endpoint.ip, src_endpoint.instance_uid come from AWS's published
-- Security Lake OCSF Route 53 samples (aws-samples/aws-security-analytics-bootstrap). Confirm against the 2.0 table.
-- Schedule: hourly via EventBridge Scheduler -> Lambda -> Athena StartQueryExecution.
SELECT
  regexp_replace(lower(query.hostname), '\.$', '') AS ai_domain,
  src_endpoint.instance_uid AS instance_id,
  src_endpoint.ip AS src_ip,
  accountid,
  region,
  count(*) AS queries,
  min(time_dt) AS first_seen,
  max(time_dt) AS last_seen
FROM "amazon_security_lake_glue_db_ap_southeast_2"."amazon_security_lake_table_ap_southeast_2_route53_2_0"
WHERE time_dt BETWEEN CURRENT_TIMESTAMP - INTERVAL '1' HOUR AND CURRENT_TIMESTAMP
  AND regexp_like(lower(query.hostname),
    '(^|\.)(api\.openai\.com|openai\.azure\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|aiplatform\.googleapis\.com|api\.mistral\.ai|api\.cohere\.(com|ai)|api\.groq\.com|api\.together\.(xyz|ai)|api\.deepseek\.com|api\.x\.ai|openrouter\.ai|api\.perplexity\.ai|api-inference\.huggingface\.co|router\.huggingface\.co|api\.fireworks\.ai)\.?$')
GROUP BY 1, 2, 3, 4, 5
ORDER BY queries DESC
LIMIT 500;

-- YUMA-GAI-G11  Shadow AI: workloads resolving third-party AI API domains
-- Status: HUNT (parsed offline). Cloud DNS query logging must be on for the VPC (DNS server policy, logging enabled).
--   Fields: queryName, sourceIP, vmInstanceName, vmProjectId  https://docs.cloud.google.com/dns/docs/monitoring
--   Query pattern from CSA 6.40.
-- Register: ${register_dataset}.ai_approved_workloads (vm_instance_name STRING)
-- Maps: ISM-2074, ISM-2134 | ATT&CK T1567 | ATLAS AML.T0040, AML.T0024 | OWASP LLM02, ASI04
WITH q AS (
  SELECT
    l.timestamp,
    RTRIM(LOWER(JSON_VALUE(l.json_payload.queryName)), '.') AS query_name,
    JSON_VALUE(l.json_payload.sourceIP) AS source_ip,
    JSON_VALUE(l.json_payload.vmInstanceName) AS vm_instance_name,
    JSON_VALUE(l.json_payload.vmProjectId) AS vm_project_id
  FROM `${logs_table}` AS l
  WHERE l.timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 DAY)
    AND l.log_id = 'dns.googleapis.com/dns_queries'
)
SELECT
  'LOW' AS severity,
  IFNULL(q.vm_instance_name, q.source_ip) AS entity,
  CONCAT(IFNULL(q.vm_instance_name, q.source_ip), ' resolved ', STRING_AGG(DISTINCT q.query_name, ', ')) AS summary,
  q.vm_instance_name, q.vm_project_id, q.source_ip,
  ARRAY_AGG(DISTINCT q.query_name) AS domains, COUNT(*) AS queries
FROM q
LEFT JOIN `${register_dataset}.ai_approved_workloads` AS ok
  ON ok.vm_instance_name = q.vm_instance_name
WHERE ok.vm_instance_name IS NULL
  AND REGEXP_CONTAINS(q.query_name, r'(^|\.)(api\.openai\.com|openai\.azure\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.mistral\.ai|api\.deepseek\.com|api\.perplexity\.ai|api\.x\.ai|api\.groq\.com|api\.together\.xyz|openrouter\.ai|api\.cohere\.com|api\.cohere\.ai|api-inference\.huggingface\.co|api\.fireworks\.ai|api\.replicate\.com)$')
GROUP BY q.vm_instance_name, q.vm_project_id, q.source_ip

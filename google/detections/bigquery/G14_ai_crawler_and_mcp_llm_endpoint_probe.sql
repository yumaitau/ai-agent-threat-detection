-- YUMA-GAI-G14  AI crawler user agents and MCP / LLM-API / agent-card endpoint probing (external Application Load Balancer)
-- Status: HUNT (parsed offline). http_request fields per CSA 6.20.
-- Maps: ISM-2116 | ATT&CK T1595.002, T1593 | ATLAS AML.T0006 | OWASP LLM10
WITH r AS (
  SELECT
    l.timestamp,
    l.http_request.remote_ip AS remote_ip,
    l.http_request.request_url AS request_url,
    l.http_request.user_agent AS user_agent,
    l.http_request.status AS status
  FROM `${logs_table}` AS l
  WHERE l.timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 DAY)
    AND l.resource.type = 'http_load_balancer'
    AND (
      REGEXP_CONTAINS(l.http_request.request_url, r'(?i)/(mcp|sse|messages|\.well-known/(mcp|agent\.json|agent-card\.json|ai-plugin\.json)|v1/(chat/completions|completions|messages|responses|models)|api/(generate|chat|tags)|openapi\.json)(\?|/|$)')
      OR REGEXP_CONTAINS(IFNULL(l.http_request.user_agent, ''), r'(?i)(GPTBot|ChatGPT-User|OAI-SearchBot|ClaudeBot|Claude-User|Claude-SearchBot|PerplexityBot|Perplexity-User|Meta-ExternalAgent|Bytespider|CCBot|Google-Agent)')
    )
)
SELECT
  IF(COUNTIF(status BETWEEN 200 AND 299 AND REGEXP_CONTAINS(request_url, r'(?i)/(mcp|sse)')) > 0, 'MEDIUM', 'LOW') AS severity,
  remote_ip AS entity,
  CONCAT(remote_ip, ' hit ', CAST(COUNT(DISTINCT request_url) AS STRING), ' AI-surface URLs') AS summary,
  remote_ip,
  COUNT(*) AS hits,
  COUNT(DISTINCT request_url) AS distinct_urls,
  ARRAY_AGG(DISTINCT request_url IGNORE NULLS LIMIT 20) AS sample_urls,
  ARRAY_AGG(DISTINCT user_agent IGNORE NULLS LIMIT 10) AS user_agents,
  ARRAY_AGG(DISTINCT status IGNORE NULLS) AS statuses
FROM r
GROUP BY remote_ip
HAVING COUNT(DISTINCT request_url) >= 5

-- Yuma AIA-A14 (Security Lake variant): AI-speed exploitation burst against WAF-protected apps
-- Table: WAFv2 logs source, version 2 (waf_2_0). Fields from AWS's Security Lake 2.0 WAF examples:
--   time_dt, action, src_endpoint.ip, src_endpoint.location.country, http_request.url.path, firewall_rule.uid, firewall_rule.type
--   https://docs.aws.amazon.com/security-lake/latest/userguide/example-queries-waf-sourceversion2.html
-- Thresholds as the Logs Insights variant (starting guesses).
SELECT src_endpoint.ip AS src_ip,
       src_endpoint.location.country AS country,
       date_trunc('hour', time_dt) + (minute(time_dt) / 10) * INTERVAL '10' MINUTE AS window_start,
       count(*) AS requests,
       count(DISTINCT http_request.url.path) AS paths,
       count(DISTINCT CASE WHEN action = 'Denied' THEN firewall_rule.uid END) AS blocking_rules,
       slice(array_agg(DISTINCT http_request.url.path), 1, 20) AS sample_paths
FROM "amazon_security_lake_glue_db_ap_southeast_2"."amazon_security_lake_table_ap_southeast_2_waf_2_0"
WHERE time_dt BETWEEN CURRENT_TIMESTAMP - INTERVAL '30' MINUTE AND CURRENT_TIMESTAMP
GROUP BY 1, 2, 3
HAVING count(DISTINCT CASE WHEN action = 'Denied' THEN firewall_rule.uid END) >= 5
    OR (count(*) >= 300 AND count(DISTINCT http_request.url.path) >= 60)
ORDER BY blocking_rules DESC, requests DESC;

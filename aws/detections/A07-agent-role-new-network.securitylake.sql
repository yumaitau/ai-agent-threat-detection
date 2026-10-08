-- Yuma AIA-A07: AI agent role used from a source IP or user agent not seen in the 14-day baseline, or by a human session
-- Agent roles normally act from AWS service principals (sourceIPAddress = service name) or fixed egress IPs.
-- A registered agent role suddenly calling APIs from a new public IP suggests stolen session credentials (ISM-2148).
-- Uses the register's identity list; joins on the session issuer (role ARN) of assumed-role sessions.
WITH agent_roles AS (
  SELECT identity_arn, agent_id, agent_name, owner FROM yuma_aia.register_identities
  WHERE identity_arn LIKE 'arn:aws:iam::%:role/%'
),
activity AS (
  SELECT t.time_dt, t.accountid, t.region, t.actor.session.issuer AS role_arn, t.src_endpoint.ip AS src_ip,
         t.http_request.user_agent AS user_agent, t.api.service.name AS service, t.api.operation AS operation
  FROM "amazon_security_lake_glue_db_ap_southeast_2"."amazon_security_lake_table_ap_southeast_2_cloud_trail_mgmt_2_0" t
  WHERE t.time_dt BETWEEN CURRENT_TIMESTAMP - INTERVAL '14' DAY AND CURRENT_TIMESTAMP
    AND t.actor.session.issuer IN (SELECT identity_arn FROM agent_roles)
),
baseline AS (
  SELECT DISTINCT role_arn, src_ip FROM activity
  WHERE time_dt < CURRENT_TIMESTAMP - INTERVAL '1' HOUR
)
SELECT a.role_arn, r.agent_id, r.agent_name, r.owner, a.src_ip,
       count(*) AS calls,
       count(DISTINCT a.operation) AS distinct_operations,
       array_agg(DISTINCT a.user_agent) AS user_agents,
       min(a.time_dt) AS first_seen
FROM activity a
JOIN agent_roles r ON r.identity_arn = a.role_arn
LEFT JOIN baseline b ON b.role_arn = a.role_arn AND b.src_ip = a.src_ip
WHERE a.time_dt >= CURRENT_TIMESTAMP - INTERVAL '1' HOUR
  AND b.src_ip IS NULL
  AND NOT regexp_like(coalesce(a.src_ip, ''), '\.amazonaws\.com$')
GROUP BY a.role_arn, r.agent_id, r.agent_name, r.owner, a.src_ip
ORDER BY calls DESC;

-- Body of BigQuery stored procedure sp_workspace_oauth_snapshot (called by PB4 daily).
-- Writes one RegisterSnapshot per Workspace OAuth client seen granting scopes in the last 90 days.
-- Status: parsed offline. Same export columns as G01 (token.client_id, token.app_name, token.scope).
-- Limitation: authorize events minus later revoke events approximate "currently granted"; the authoritative list is
--   Directory API tokens.list per user (https://developers.google.com/workspace/admin/directory/reference/rest/v1/tokens/list).
INSERT INTO `${register_dataset}.ai_agent_register`
  (record_time, record_type, agent_key, agent_name, source, platform, oauth_client_id, permissions, shared_with,
   consent_type, consented_by, consent_time, owners, identities, user_accounts_and_credentials, declared_tools,
   mcp_servers, data_sources, risk_rating, notes)
WITH ev AS (
  SELECT a.time_usec, a.email, a.event_name, a.token.client_id AS client_id, a.token.app_name AS app_name, scope
  FROM `${workspace_activity_table}` AS a
  LEFT JOIN UNNEST(a.token.scope) AS scope
  WHERE a._PARTITIONTIME >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 90 DAY)
    AND a.record_type = 'token'
    AND a.event_name IN ('authorize', 'revoke')
),
last_state AS (
  SELECT client_id, email, ARRAY_AGG(event_name ORDER BY time_usec DESC LIMIT 1)[OFFSET(0)] AS last_event
  FROM ev GROUP BY client_id, email
),
granted AS (
  SELECT ev.* FROM ev
  JOIN last_state AS s USING (client_id, email)
  WHERE s.last_event = 'authorize' AND ev.event_name = 'authorize'
)
SELECT
  CURRENT_TIMESTAMP(), 'RegisterSnapshot', CONCAT('oauth:', client_id), ANY_VALUE(app_name), 'WorkspaceOAuth', 'WorkspaceApp', client_id,
  ARRAY_AGG(DISTINCT scope IGNORE NULLS),
  ARRAY_AGG(DISTINCT email IGNORE NULLS LIMIT 500),
  'UserConsent',
  ARRAY_AGG(email ORDER BY time_usec LIMIT 1)[OFFSET(0)],
  TIMESTAMP_MICROS(MIN(time_usec)),
  ARRAY<STRING>[], ARRAY<STRING>[], ARRAY<STRING>[], ARRAY<STRING>[], ARRAY<STRING>[], ARRAY<STRING>[],
  IF(LOGICAL_OR(REGEXP_CONTAINS(IFNULL(scope, ''), r'(?i)(mail\.google\.com/|/auth/(gmail|drive$|admin\.|cloud-platform))')), 'High', 'Medium'),
  'PB4: from Workspace token authorize events, last 90 days'
FROM granted
GROUP BY client_id;

-- PB2 six-monthly review list (ISM-2138): OAuth apps and agents whose last review is missing or older than ~6 months,
-- with how much each app is still used (unused apps should be revoked). Run monthly; send the list to owners.
-- Status: parsed offline.
WITH use30 AS (
  SELECT a.token.client_id AS client_id, COUNT(*) AS api_calls_30d, COUNT(DISTINCT a.email) AS users_30d
  FROM `${workspace_activity_table}` AS a
  WHERE a._PARTITIONTIME >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
    AND a.record_type = 'token' AND a.event_name = 'activity'
  GROUP BY client_id
)
SELECT r.agent_key, r.agent_name, r.source, r.owners, r.permissions, r.review_status, r.last_review_time,
       IFNULL(u.api_calls_30d, 0) AS api_calls_30d, IFNULL(u.users_30d, 0) AS users_30d,
       IF(IFNULL(u.api_calls_30d, 0) = 0 AND r.source = 'WorkspaceOAuth', 'Revoke candidate (unused 30d)', 'Review') AS suggested_action
FROM `${register_dataset}.v_register_current` AS r
LEFT JOIN use30 AS u ON u.client_id = r.oauth_client_id
WHERE NOT r.is_retired AND r.review_status IN ('NeverReviewed', 'Overdue', 'DueSoon')
ORDER BY r.review_status, api_calls_30d

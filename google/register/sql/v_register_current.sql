-- Current state of every AI agent / AI app in the register, with ISM-2133/2135/2138 gap flags.
-- Status: parsed offline (sqlglot BigQuery). Placeholder: ${register_dataset}
WITH snap AS (
  SELECT * FROM `${register_dataset}.ai_agent_register`
  WHERE record_type = 'RegisterSnapshot'
  QUALIFY ROW_NUMBER() OVER (PARTITION BY agent_key ORDER BY record_time DESC) = 1
),
dec AS (
  SELECT agent_key, decision, decision_by, decision_reason, record_time AS decision_time, case_ref
  FROM `${register_dataset}.ai_agent_register`
  WHERE record_type IN ('ConsentDecision', 'ContainmentDecision')
  QUALIFY ROW_NUMBER() OVER (PARTITION BY agent_key ORDER BY record_time DESC) = 1
),
rev AS (
  SELECT agent_key, MAX(record_time) AS last_review_time
  FROM `${register_dataset}.ai_agent_register`
  WHERE record_type = 'ReviewCompleted'
  GROUP BY agent_key
),
ret AS (
  SELECT agent_key, MAX(record_time) AS retired_time
  FROM `${register_dataset}.ai_agent_register`
  WHERE record_type = 'Retired'
  GROUP BY agent_key
),
sa_share AS (
  SELECT LOWER(service_account) AS sa, COUNT(DISTINCT agent_key) AS agents_on_sa
  FROM snap WHERE service_account IS NOT NULL GROUP BY sa
)
SELECT
  s.agent_key, s.agent_name, s.source, s.platform, s.project_id, s.location, s.oauth_client_id,
  s.identity_type, s.effective_identity, s.service_account, s.service_account_unique_id,
  s.owners, s.business_purpose, s.identities, s.user_accounts_and_credentials, s.permissions,
  s.declared_tools, s.mcp_servers, s.data_sources, s.shared_with, s.lifecycle_status,
  s.consent_type, s.consented_by, s.consent_time, s.risk_rating,
  s.record_time AS last_seen,
  d.decision, d.decision_by, d.decision_reason, d.decision_time, d.case_ref,
  rv.last_review_time,
  (ret.retired_time IS NOT NULL AND ret.retired_time >= s.record_time) AS is_retired,
  -- ISM-2133: own identity. Agent Identity is unique by design; a shared service agent, a service account shared by
  -- several agents, or domain-wide delegation (acts as users) are gaps.
  (
    s.source = 'WorkspaceDWD'
    OR (s.source = 'AgentRuntime' AND IFNULL(s.identity_type, 'IDENTITY_TYPE_UNSPECIFIED') <> 'AGENT_IDENTITY'
        AND (s.service_account IS NULL OR REGEXP_CONTAINS(IFNULL(s.effective_identity, ''), r'gcp-sa-aiplatform-re\.')))
    OR IFNULL(sh.agents_on_sa, 0) > 1
  ) AS gap_no_unique_identity,
  -- ISM-2135 content gaps
  ARRAY_LENGTH(IFNULL(s.owners, [])) = 0 AS gap_no_owner,
  IFNULL(s.business_purpose, '') = '' AS gap_no_purpose,
  ARRAY_LENGTH(IFNULL(s.permissions, [])) = 0 AS gap_no_permissions_recorded,
  (s.source IN ('AgentRuntime', 'GeminiEnterprise', 'AgentRegistry') AND ARRAY_LENGTH(IFNULL(s.declared_tools, [])) = 0) AS gap_no_tools_recorded,
  ARRAY_LENGTH(IFNULL(s.data_sources, [])) = 0 AS gap_no_data_sources_recorded,
  -- ISM-2138 six-monthly review
  CASE
    WHEN rv.last_review_time IS NULL THEN 'NeverReviewed'
    WHEN rv.last_review_time < TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 183 DAY) THEN 'Overdue'
    WHEN rv.last_review_time < TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 153 DAY) THEN 'DueSoon'
    ELSE 'Current'
  END AS review_status,
  (d.decision IS NULL OR d.decision IN ('Pending', 'Investigate')) AS undecided,
  s.record_time < TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 2 DAY) AS stale_in_sync
FROM snap AS s
LEFT JOIN dec AS d USING (agent_key)
LEFT JOIN rev AS rv USING (agent_key)
LEFT JOIN ret USING (agent_key)
LEFT JOIN sa_share AS sh ON sh.sa = LOWER(s.service_account)

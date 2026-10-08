-- One row per ISM control (2133-2140, 2156-2159) with an automated status where the pack can measure it.
-- Status: parsed offline. Statuses: Met | Gap | Partial | Attestation required. "Met" is a signal, not an audit opinion.
WITH r AS (SELECT * FROM `${register_dataset}.v_register_current` WHERE NOT is_retired),
h AS (
  SELECT detection_id, COUNT(*) AS hits_30d
  FROM `${register_dataset}.detection_hits`
  WHERE hit_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
  GROUP BY detection_id
),
m AS (
  SELECT
    COUNT(*) AS agents,
    COUNTIF(gap_no_unique_identity) AS no_unique_identity,
    COUNTIF(gap_no_owner OR gap_no_purpose OR gap_no_permissions_recorded OR gap_no_tools_recorded OR gap_no_data_sources_recorded) AS content_gaps,
    COUNTIF(review_status IN ('Overdue', 'NeverReviewed') AND source IN ('WorkspaceOAuth', 'WorkspaceDWD')) AS oauth_review_overdue,
    COUNTIF(stale_in_sync) AS stale,
    MAX(last_seen) AS last_sync
  FROM r
),
hits AS (
  SELECT
    IFNULL((SELECT hits_30d FROM h WHERE detection_id = 'G01'), 0) AS g01,
    IFNULL((SELECT hits_30d FROM h WHERE detection_id = 'G04'), 0) AS g04,
    IFNULL((SELECT hits_30d FROM h WHERE detection_id = 'G06'), 0) AS g06,
    IFNULL((SELECT hits_30d FROM h WHERE detection_id = 'G08'), 0) AS g08,
    IFNULL((SELECT hits_30d FROM h WHERE detection_id = 'G15'), 0) AS g15
)
SELECT c.control_id, c.theme, c.evidence_method,
  CASE c.control_id
    WHEN 'ISM-2133' THEN IF(m.no_unique_identity = 0, 'Met', 'Gap')
    WHEN 'ISM-2134' THEN IF(m.last_sync >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 2 DAY), 'Met', 'Gap')
    WHEN 'ISM-2135' THEN IF(m.content_gaps = 0, 'Met', 'Gap')
    WHEN 'ISM-2136' THEN IF(hits.g15 = 0, 'Partial', 'Gap')
    WHEN 'ISM-2137' THEN IF(hits.g01 = 0, 'Met', 'Gap')
    WHEN 'ISM-2138' THEN IF(m.oauth_review_overdue = 0, 'Met', 'Gap')
    WHEN 'ISM-2139' THEN 'Partial'
    WHEN 'ISM-2140' THEN 'Attestation required'
    WHEN 'ISM-2156' THEN IF(hits.g06 = 0, 'Partial', 'Gap')
    WHEN 'ISM-2157' THEN IF(hits.g04 = 0, 'Partial', 'Gap')
    WHEN 'ISM-2158' THEN IF(hits.g08 = 0, 'Partial', 'Gap')
    WHEN 'ISM-2159' THEN 'Partial'
  END AS status,
  CASE c.control_id
    WHEN 'ISM-2133' THEN CONCAT(CAST(m.no_unique_identity AS STRING), ' of ', CAST(m.agents AS STRING), ' agents without a unique identity')
    WHEN 'ISM-2134' THEN CONCAT('Last register sync ', CAST(m.last_sync AS STRING), '; ', CAST(m.stale AS STRING), ' stale entries')
    WHEN 'ISM-2135' THEN CONCAT(CAST(m.content_gaps AS STRING), ' agents missing owner, purpose, permissions, tools or data sources')
    WHEN 'ISM-2137' THEN CONCAT(CAST(hits.g01 AS STRING), ' user-granted sensitive AI app consents in 30 days')
    WHEN 'ISM-2138' THEN CONCAT(CAST(m.oauth_review_overdue AS STRING), ' OAuth apps overdue for six-monthly review')
    WHEN 'ISM-2156' THEN CONCAT(CAST(hits.g06 AS STRING), ' sensitive role grants to AI identities in 30 days')
    WHEN 'ISM-2157' THEN CONCAT(CAST(hits.g04 AS STRING), ' AI app data-pull bursts in 30 days')
    WHEN 'ISM-2158' THEN CONCAT(CAST(hits.g08 AS STRING), ' injection-then-action correlations in 30 days')
    WHEN 'ISM-2136' THEN CONCAT(CAST(hits.g15 AS STRING), ' off-Google key uses by AI service accounts in 30 days')
    ELSE c.pack_evidence
  END AS evidence_note,
  c.control_text
FROM `${register_dataset}.ism_control_map` AS c
CROSS JOIN m
CROSS JOIN hits

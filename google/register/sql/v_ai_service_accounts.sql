-- Identities (service accounts, agent principals) that belong to AI agents. Used by G06, G07, G15 and the SecOps
-- reference list %yuma_ai_service_accounts (PB4 exports this view to the list).
-- Status: parsed offline.
SELECT DISTINCT
  agent_key,
  LOWER(service_account) AS service_account_email,
  service_account_unique_id,
  member
FROM `${register_dataset}.v_register_current`
CROSS JOIN UNNEST(ARRAY_CONCAT(
  IF(service_account IS NULL, [], [CONCAT('serviceAccount:', LOWER(service_account))]),
  IF(effective_identity IS NULL, [], [IF(STARTS_WITH(effective_identity, 'agents.global'),
                                         CONCAT('principal://', effective_identity),
                                         CONCAT('serviceAccount:', LOWER(effective_identity)))]),
  IFNULL(identities, []))) AS member
WHERE NOT is_retired

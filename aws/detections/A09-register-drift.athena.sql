-- Yuma AIA-A09: Register drift and ISM-2135 gaps
-- Compares PB4's latest daily inventory snapshot (what exists in AWS) with the curated register (what is approved).
-- Tables are defined in register/athena-register.sql.
WITH inv AS (
  SELECT * FROM yuma_aia.inventory
  WHERE snapshot_date = (SELECT max(snapshot_date) FROM yuma_aia.inventory)
)
SELECT
  coalesce(i.resource_arn, r.agent_id) AS agent_id,
  coalesce(i.platform, r.platform) AS platform,
  coalesce(i.name, r.agent_name) AS name,
  r.owner,
  r.business_purpose,
  r.status AS register_status,
  r.next_review_due,
  CASE
    WHEN r.agent_id IS NULL THEN 'Unregistered: exists in AWS, not in register (ISM-2134)'
    WHEN i.resource_arn IS NULL AND r.status <> 'Retired' THEN 'Stale: in register, not found in AWS'
    WHEN r.owner IS NULL OR r.business_purpose IS NULL THEN 'Incomplete: owner or purpose missing (ISM-2135)'
    WHEN r.identities IS NULL OR cardinality(r.identities) = 0 THEN 'Incomplete: no identity recorded (ISM-2133, 2135)'
    WHEN r.tools IS NULL OR r.permissions IS NULL THEN 'Incomplete: tools or permissions missing (ISM-2135, 2156)'
    WHEN i.role_arn IS NOT NULL AND NOT contains(r.identities, i.role_arn) THEN 'Drift: runtime role differs from register'
    WHEN r.next_review_due < current_date THEN 'Review overdue (6-monthly)'
    ELSE 'OK'
  END AS finding
FROM inv i
FULL OUTER JOIN yuma_aia.register_current r ON r.agent_id = i.resource_arn
ORDER BY finding, platform, name;

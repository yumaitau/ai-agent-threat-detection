-- Yuma AI agent register in Athena.
-- PB4 writes two JSON Lines snapshots each day to the customer's evidence bucket:
--   s3://<evidence-bucket>/register/snapshot_date=YYYY-MM-DD/register.jsonl   (CURRENT items from DynamoDB)
--   s3://<evidence-bucket>/inventory/snapshot_date=YYYY-MM-DD/inventory.jsonl (what exists in AWS today)
-- Partition projection avoids crawlers:
--   https://docs.aws.amazon.com/athena/latest/ug/partition-projection.html
-- Replace <evidence-bucket>. Run each statement separately in Athena.

CREATE DATABASE IF NOT EXISTS yuma_aia;

CREATE EXTERNAL TABLE IF NOT EXISTS yuma_aia.register_snapshots (
  agent_id string,
  agent_name string,
  platform string,
  account_id string,
  region string,
  owner string,
  business_purpose string,
  identities array<string>,
  credentials array<string>,
  tools array<string>,
  permissions array<string>,
  data_repositories array<string>,
  approved_models array<string>,
  record_type string,
  status string,
  decided_by string,
  decided_at string,
  last_review date,
  next_review_due date,
  updated_at string
)
PARTITIONED BY (snapshot_date string)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
LOCATION 's3://<evidence-bucket>/register/'
TBLPROPERTIES (
  'projection.enabled' = 'true',
  'projection.snapshot_date.type' = 'date',
  'projection.snapshot_date.format' = 'yyyy-MM-dd',
  'projection.snapshot_date.range' = '2026-01-01,NOW',
  'projection.snapshot_date.interval' = '1',
  'projection.snapshot_date.interval.unit' = 'DAYS',
  'storage.location.template' = 's3://<evidence-bucket>/register/snapshot_date=${snapshot_date}/'
);

CREATE EXTERNAL TABLE IF NOT EXISTS yuma_aia.inventory (
  resource_arn string,
  platform string,
  name string,
  role_arn string,
  account_id string,
  region string,
  created_at string,
  details string
)
PARTITIONED BY (snapshot_date string)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
LOCATION 's3://<evidence-bucket>/inventory/'
TBLPROPERTIES (
  'projection.enabled' = 'true',
  'projection.snapshot_date.type' = 'date',
  'projection.snapshot_date.format' = 'yyyy-MM-dd',
  'projection.snapshot_date.range' = '2026-01-01,NOW',
  'projection.snapshot_date.interval' = '1',
  'projection.snapshot_date.interval.unit' = 'DAYS',
  'storage.location.template' = 's3://<evidence-bucket>/inventory/snapshot_date=${snapshot_date}/'
);

CREATE OR REPLACE VIEW yuma_aia.register_current AS
SELECT *
FROM yuma_aia.register_snapshots
WHERE snapshot_date = (SELECT max(snapshot_date) FROM yuma_aia.register_snapshots
                       WHERE snapshot_date >= date_format(current_date - INTERVAL '7' DAY, '%Y-%m-%d'));

CREATE OR REPLACE VIEW yuma_aia.register_identities AS
SELECT r.agent_id, r.agent_name, r.owner, r.status, i.identity_arn
FROM yuma_aia.register_current r
CROSS JOIN UNNEST(r.identities) AS i(identity_arn)
WHERE r.status IN ('Approved', 'PendingReview', 'Contained');

-- ISM view used by PB5 and the dashboard: one row per agent with ISM-2135 gaps and review state
CREATE OR REPLACE VIEW yuma_aia.register_ism AS
SELECT agent_id, agent_name, platform, owner, status, next_review_due,
       owner IS NULL OR business_purpose IS NULL AS gap_owner_purpose,
       identities IS NULL OR cardinality(identities) = 0 AS gap_identity,
       credentials IS NULL AS gap_credentials,
       tools IS NULL OR permissions IS NULL AS gap_tools_permissions,
       data_repositories IS NULL AS gap_data_repositories,
       CASE WHEN last_review IS NULL THEN 'Never reviewed'
            WHEN next_review_due < current_date THEN 'Overdue'
            WHEN next_review_due < current_date + INTERVAL '30' DAY THEN 'Due within 30 days'
            ELSE 'Current' END AS review_status
FROM yuma_aia.register_current
WHERE status <> 'Retired';

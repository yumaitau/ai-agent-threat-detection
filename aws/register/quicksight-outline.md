# QuickSight outline (optional, for customers who already license QuickSight)

The CloudWatch dashboard (`cloudwatch-dashboard.json`) is the default because it costs nothing extra. QuickSight suits
executive or assessor reporting. Nothing here has been built or tested.

**Data sources (Athena):** `yuma_aia.register_ism`, `yuma_aia.register_current`, `yuma_aia.inventory`
(see `athena-register.sql`). Optional: the evidence CSVs in `evidence/YYYY-MM-DD/` as an S3 data source.

**Datasets:**
1. Register (SPICE, daily refresh after PB4 runs at 06:30 Sydney time): one row per agent with gap flags and review status.
2. Drift: the A09 query (`detections/A09-register-drift.athena.sql`) as a custom SQL dataset.
3. Controls: `ism-controls.csv` from the latest evidence folder (manual refresh monthly after PB5).

**Sheets:**
- *Overview:* KPIs (agents, pending review, incomplete, overdue reviews), agents by platform, controls by status.
- *Register:* table with conditional formatting on the gap columns; filter by platform, owner, status.
- *ISM coverage:* one row per control (ISM-2133 to 2140, 2156 to 2159) with status, metric and evidence method.
- *Review status:* agents by review_status and next_review_due; list of reviews due within 30 days.
- *Drift:* Unregistered, Stale, Incomplete and role-drift findings from A09.

**Access:** restrict to the security team and control owners. Row-level security by account_id if the customer
runs one register across several accounts.

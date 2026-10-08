# Looker Studio dashboard: AI agents and ISM AI controls (outline)

**Data sources** (BigQuery connector; the viewer's credentials or a service account with dataViewer on the register):
- `v_ism_control_status`
- `v_register_current`
- `detection_hits`
- `ai_agent_register`, filtered to decision rows

## Page 1: ISM AI controls

- **Scorecards:** count of controls by status (Met, Gap, Partial, Attestation required).
- **Table:** control_id, theme, status, evidence_note. Colour status with conditional formatting.
- **Text box:** "Automated signals, not an assessment. ISM-2140 needs owner attestation."

## Page 2: Agent register

- **Scorecards:** agents by `source` (AgentRuntime, GeminiEnterprise, WorkspaceOAuth, WorkspaceDWD).
- **Bar chart:** gap counts, one bar per gap: gap_no_unique_identity, gap_no_owner, gap_no_purpose, gap_no_permissions_recorded, gap_no_tools_recorded, gap_no_data_sources_recorded.
- **Table:** agent_key, agent_name, source, identity_type, owners, risk_rating, decision, review_status, last_seen.
- **Filters:** source, project_id, risk_rating, review_status.
- **Pie chart:** `identity_type` for Agent Runtime agents. AGENT_IDENTITY is the target state for ISM-2133.

## Page 3: Detections

- **Time series:** hits per day, broken down by detection_id.
- **Table:** latest 200 hits, showing hit_time (Australia/Sydney), detection_id, severity, entity, summary, case_ref.
- **Heat map:** detection_id × severity.

## Page 4: Decisions (ISM-2113 / 2138)

- **Table:** record_time, record_type, agent_key, decision, decision_by, decision_reason, case_ref.
- **Scorecards:** pending decisions; reviews overdue.

**Status:** outline only. No report file is shipped, because Looker Studio reports aren't portable as files. Build it in about an hour from this outline.

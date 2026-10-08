-- Single-row Markdown summary used by PB5 (monthly evidence export) as summary.md.
-- Status: parsed offline.
SELECT CONCAT(
  '# ISM AI agent controls - evidence summary\n\n',
  'Generated: ', FORMAT_TIMESTAMP('%Y-%m-%d %H:%M %Z', CURRENT_TIMESTAMP(), 'Australia/Sydney'), '\n\n',
  '| Control | Status | Evidence |\n|---|---|---|\n',
  STRING_AGG(CONCAT('| ', control_id, ' | ', status, ' | ', REPLACE(IFNULL(evidence_note, ''), '|', '/'), ' |'), '\n' ORDER BY control_id),
  '\n\nStatuses are automated signals from the AI agent register and detections, not an assessor opinion. ',
  'ISM-2140 needs a control-owner attestation.\n'
) AS summary_md
FROM `${register_dataset}.v_ism_control_status`

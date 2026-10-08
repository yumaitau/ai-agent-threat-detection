-- PB2 (no-SecOps path, scheduled hourly): every new G01 / G09 hit that has no decision yet becomes a Pending ConsentDecision,
-- so the register shows it and PB2's notifier (or an analyst) can approve, revoke or investigate.
-- Status: parsed offline.
INSERT INTO `${register_dataset}.ai_agent_register` (record_time, record_type, agent_key, decision, decision_by, decision_reason, case_ref, notes)
SELECT
  CURRENT_TIMESTAMP(), 'ConsentDecision', h.entity, 'Pending', 'pb2-automation',
  CONCAT('New ', h.detection_id, ' hit awaiting owner/administrator decision'), NULL, h.summary
FROM `${register_dataset}.detection_hits` AS h
LEFT JOIN `${register_dataset}.ai_agent_register` AS r
  ON r.agent_key = h.entity AND r.record_type = 'ConsentDecision'
WHERE h.detection_id IN ('G01', 'G09')
  AND h.hit_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 2 HOUR)
  AND r.agent_key IS NULL
QUALIFY ROW_NUMBER() OVER (PARTITION BY h.entity ORDER BY h.hit_time) = 1;

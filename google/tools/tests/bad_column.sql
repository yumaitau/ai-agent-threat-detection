-- negative test: invented columns
SELECT l.made_up_column, l.proto_payload.audit_log.not_a_field, a.token.invented_param
FROM `${logs_table}` AS l CROSS JOIN `${workspace_activity_table}` AS a

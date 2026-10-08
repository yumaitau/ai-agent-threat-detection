-- negative test: broken SQL
SELECT a.email, FROM `${workspace_activity_table}` AS a WHERE (a.record_type = 'token'

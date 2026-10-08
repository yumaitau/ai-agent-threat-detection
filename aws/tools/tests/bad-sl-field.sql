-- negative control: actor.user.arn is not a documented OCSF field (actor.user.uid is)
SELECT actor.user.arn, api.operation FROM "amazon_security_lake_glue_db_ap_southeast_2"."amazon_security_lake_table_ap_southeast_2_cloud_trail_mgmt_2_0"
WHERE time_dt > CURRENT_TIMESTAMP - INTERVAL '1' HOUR;

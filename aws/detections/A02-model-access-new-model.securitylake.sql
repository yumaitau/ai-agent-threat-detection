-- Yuma AIA-A02: First-seen principal + model pair for Bedrock runtime calls not approved in the register
-- InvokeModel, InvokeModelWithResponseStream, Converse and ConverseStream are CloudTrail MANAGEMENT events,
-- so they reach Security Lake's cloud_trail_mgmt_2_0 source.
--   https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html
-- modelId is in the request parameters (api.request.data JSON). Register view: yuma_aia.register_current (register/athena-register.sql).
WITH recent AS (
  SELECT coalesce(actor.session.issuer, actor.user.uid) AS principal,
         json_extract_scalar(api.request.data, '$.modelId') AS model_id,
         api.operation AS operation,
         count(*) AS calls,
         min(time_dt) AS first_call
  FROM "amazon_security_lake_glue_db_ap_southeast_2"."amazon_security_lake_table_ap_southeast_2_cloud_trail_mgmt_2_0"
  WHERE time_dt BETWEEN CURRENT_TIMESTAMP - INTERVAL '1' HOUR AND CURRENT_TIMESTAMP
    AND api.service.name = 'bedrock.amazonaws.com'
    AND api.operation IN ('InvokeModel', 'InvokeModelWithResponseStream', 'Converse', 'ConverseStream')
    AND api.response.error IS NULL
  GROUP BY 1, 2, 3
),
baseline AS (
  SELECT DISTINCT coalesce(actor.session.issuer, actor.user.uid) AS principal,
         json_extract_scalar(api.request.data, '$.modelId') AS model_id
  FROM "amazon_security_lake_glue_db_ap_southeast_2"."amazon_security_lake_table_ap_southeast_2_cloud_trail_mgmt_2_0"
  WHERE time_dt BETWEEN CURRENT_TIMESTAMP - INTERVAL '14' DAY AND CURRENT_TIMESTAMP - INTERVAL '1' HOUR
    AND api.service.name = 'bedrock.amazonaws.com'
    AND api.operation IN ('InvokeModel', 'InvokeModelWithResponseStream', 'Converse', 'ConverseStream')
)
SELECT r.principal, r.model_id, r.operation, r.calls, r.first_call,
       reg.agent_id, reg.owner, reg.approved_models
FROM recent r
LEFT JOIN baseline b ON b.principal = r.principal AND b.model_id = r.model_id
LEFT JOIN yuma_aia.register_current reg ON contains(reg.identities, r.principal)
WHERE b.principal IS NULL
  AND (reg.agent_id IS NULL OR reg.approved_models IS NULL OR NOT contains(reg.approved_models, r.model_id))
ORDER BY r.calls DESC;

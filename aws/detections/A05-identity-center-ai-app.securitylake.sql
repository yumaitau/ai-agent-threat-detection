-- Yuma AIA-A05: IAM Identity Center application created, assigned, granted scopes or opened to all users
-- The AWS analogue of third-party OAuth app consent (ISM-2137, 2138, 2139). Identity Center is where customer-managed
-- OAuth/SAML apps (including AI SaaS and MCP clients) get grants and access scopes.
-- Event names: https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-info-in-cloudtrail.html (event source sso.amazonaws.com)
-- Identity Center is regional: query the region where the instance lives.
SELECT time_dt,
       accountid,
       region,
       api.operation AS operation,
       actor.user.uid AS actor_arn,
       actor.user.name AS actor_name,
       src_endpoint.ip AS src_ip,
       json_extract_scalar(api.request.data, '$.applicationArn') AS application_arn,
       json_extract_scalar(api.request.data, '$.name') AS application_name,
       json_extract_scalar(api.request.data, '$.principalType') AS principal_type,
       json_extract_scalar(api.request.data, '$.principalId') AS principal_id,
       json_extract_scalar(api.request.data, '$.grantType') AS grant_type,
       json_extract_scalar(api.request.data, '$.scope') AS access_scope,
       json_extract_scalar(api.request.data, '$.assignmentRequired') AS assignment_required,
       api.request.data AS raw_request
FROM "amazon_security_lake_glue_db_ap_southeast_2"."amazon_security_lake_table_ap_southeast_2_cloud_trail_mgmt_2_0"
WHERE time_dt BETWEEN CURRENT_TIMESTAMP - INTERVAL '1' DAY AND CURRENT_TIMESTAMP
  AND api.service.name = 'sso.amazonaws.com'
  AND api.operation IN ('CreateApplication', 'CreateApplicationAssignment', 'PutApplicationGrant', 'PutApplicationAccessScope',
                        'PutApplicationAuthenticationMethod', 'PutApplicationAssignmentConfiguration')
  AND api.response.error IS NULL
ORDER BY time_dt DESC;

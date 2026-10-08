-- negative control: OCSF WAF has http_request.url.path, not http_request.uri
SELECT http_request.uri FROM "amazon_security_lake_glue_db_ap_southeast_2"."amazon_security_lake_table_ap_southeast_2_waf_2_0";

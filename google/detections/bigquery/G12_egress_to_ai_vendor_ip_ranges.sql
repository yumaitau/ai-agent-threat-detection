-- YUMA-GAI-G12  VPC Flow Logs egress to AI vendor IP ranges (catches hard-coded IPs / DoH that bypass Cloud DNS)
-- Status: SPEC/HUNT (parsed offline). Needs VPC Flow Logs and a maintained CIDR table; vendor ranges change and many vendors sit
--   behind shared CDNs, so expect noise. Field paths from CSA 6.01 (json_payload.connection.src_ip / dest_ip).
-- Register: ${register_dataset}.ai_vendor_cidrs (vendor STRING, cidr STRING e.g. '203.0.113.0/24', prefix INT64, network STRING)
-- Maps: ISM-2074 | ATT&CK T1567 | ATLAS AML.T0024
WITH f AS (
  SELECT
    l.timestamp,
    JSON_VALUE(l.json_payload.connection.src_ip) AS src_ip,
    JSON_VALUE(l.json_payload.connection.dest_ip) AS dest_ip,
    JSON_VALUE(l.json_payload.src_instance.vm_name) AS vm_name,
    SAFE_CAST(JSON_VALUE(l.json_payload.bytes_sent) AS INT64) AS bytes_sent
  FROM `${logs_table}` AS l
  WHERE l.timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 DAY)
    AND l.log_id = 'compute.googleapis.com/vpc_flows'
)
SELECT
  'LOW' AS severity,
  IFNULL(f.vm_name, f.src_ip) AS entity,
  CONCAT(IFNULL(f.vm_name, f.src_ip), ' sent ', CAST(SUM(f.bytes_sent) AS STRING), ' bytes to ', c.vendor) AS summary,
  f.vm_name, f.src_ip, c.vendor, SUM(f.bytes_sent) AS bytes_sent, COUNT(*) AS flows
FROM f
JOIN `${register_dataset}.ai_vendor_cidrs` AS c
  ON NET.IP_TRUNC(NET.SAFE_IP_FROM_STRING(f.dest_ip), c.prefix) = NET.IP_FROM_STRING(c.network)
GROUP BY f.vm_name, f.src_ip, c.vendor

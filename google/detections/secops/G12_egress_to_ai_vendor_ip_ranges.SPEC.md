# G12 – Egress to AI vendor IP ranges (SecOps spec, not a rule)

Status: spec only. Use the BigQuery hunt `detections/bigquery/G12_egress_to_ai_vendor_ip_ranges.sql`.

For SecOps, the shape would be:
- Log type: `GCP_VPC_FLOW`.
- Filter on `target.ip` in a CIDR reference list, e.g. `%yuma_ai_vendor_cidrs`, using `net.ip_in_range_cidr` against each entry or a CIDR-type list.
- Group with `match: principal.ip over 24h`.

The GCP_VPC_FLOW UDM mapping has not been checked for this pack, so no rule is shipped. Vendor ranges also churn, and many AI APIs sit behind shared CDNs. G11 (DNS) is the better signal. Only build this one where DNS is bypassed.

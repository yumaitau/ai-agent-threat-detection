# Google SecOps dashboard: AI threats (outline)

Native dashboards in SecOps use UDM and detection data. Panels below assume the G-rules are deployed with `yuma_id` in `meta`.

| Panel | Type | Query idea (UDM search / YARA-L dashboard query) |
|---|---|---|
| AI detections by rule | Bar | detections where rule name starts `yuma_gai_`, grouped by rule, last 30 days |
| Workspace agent actions | Time series | `principal.ai.type = "AGENT"` events by `principal.ai.display_name` |
| OAuth AI app grants | Table | `metadata.product_name = "token"` and `metadata.product_event_type = "authorize"`, by `target.resource.name` and count of distinct users |
| Model Armor matches | Time series | `metadata.log_type = "GCP_MODEL_ARMOR"`, by `security_result.description` |
| Cloud Armor top blocked IPs | Table | `metadata.log_type = "GCP_LOADBALANCING"` and `security_result.action = "BLOCK"`, by `principal.ip` |
| AI identity IAM changes | Table | `GCP_CLOUDAUDIT` SetIamPolicy where `target.user.userid` matches `agents.global` or `gcp-sa-aiplatform` |
| SCC AI Protection findings | Table | SCC findings ingested to SecOps, category matching AI / Agentic |

The register and ISM status stay in BigQuery and Looker Studio, because SecOps isn't a register. Link to the Looker report from the dashboard header.

**Status:** outline only. The field names come from the parser pages cited in the rules. Dashboard query syntax hasn't been tested in a tenant.

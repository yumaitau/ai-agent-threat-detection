# Detections as BigQuery scheduled queries writing to detection_hits, plus an org log sink -> Pub/Sub for G06/G07 near-real-time.
locals {
  rule_grade = {
    G01 = { file = "G01_ai_oauth_app_sensitive_workspace_scopes.sql", schedule = "every 1 hours", suppress_hours = 24 }
    G04 = { file = "G04_agent_oauth_data_pull_burst.sql", schedule = "every 1 hours", suppress_hours = 6 }
    G06 = { file = "G06_sensitive_role_granted_to_ai_agent_identity.sql", schedule = "every 1 hours", suppress_hours = 1 }
    G07 = { file = "G07_static_key_created_for_ai_service_account.sql", schedule = "every 1 hours", suppress_hours = 1 }
    G08 = { file = "G08_model_armor_injection_then_high_impact_action.sql", schedule = "every 1 hours", suppress_hours = 3 }
    G13 = { file = "G13_ai_speed_exploitation_burst_cloud_armor.sql", schedule = "every 10 minutes", suppress_hours = 1 }
  }
  hunts = {
    G02 = { file = "G02_domain_wide_delegation_granted.sql", schedule = "every 24 hours", suppress_hours = 24 }
    G05 = { file = "G05_gemini_workspace_use_outside_approved_users.sql", schedule = "every 24 hours", suppress_hours = 168 }
    G09 = { file = "G09_agent_deployed_or_changed_outside_register.sql", schedule = "every 24 hours", suppress_hours = 24 }
    G10 = { file = "G10_model_invocation_abuse_llmjacking.sql", schedule = "every 1 hours", suppress_hours = 24 }
    G11 = { file = "G11_shadow_ai_api_dns_from_workloads.sql", schedule = "every 24 hours", suppress_hours = 168 }
    G12 = { file = "G12_egress_to_ai_vendor_ip_ranges.sql", schedule = "every 24 hours", suppress_hours = 168 }
    G14 = { file = "G14_ai_crawler_and_mcp_llm_endpoint_probe.sql", schedule = "every 24 hours", suppress_hours = 24 }
    G15 = { file = "G15_ai_service_account_key_used_off_google.sql", schedule = "every 24 hours", suppress_hours = 24 }
  }
  scheduled = merge(local.rule_grade, var.enable_hunts ? local.hunts : {})
}

resource "google_service_account" "detections" {
  account_id   = "yuma-gai-detections"
  display_name = "AI pack scheduled detections"
}

resource "google_project_iam_member" "detections_jobuser" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = google_service_account.detections.member
}

# Read access to the log and Workspace datasets. Project-level for the skeleton; narrow to the two datasets in production.
resource "google_project_iam_member" "detections_viewer" {
  project = var.project_id
  role    = "roles/bigquery.dataViewer"
  member  = google_service_account.detections.member
}

resource "google_bigquery_dataset_iam_member" "detections_register" {
  dataset_id = google_bigquery_dataset.register.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = google_service_account.detections.member
}

resource "google_bigquery_data_transfer_config" "detection" {
  for_each             = local.scheduled
  display_name         = "yuma-gai-${each.key}"
  location             = var.bq_location
  data_source_id       = "scheduled_query"
  schedule             = each.value.schedule
  service_account_name = google_service_account.detections.email
  params = {
    query = <<-SQL
      INSERT INTO `${local.register_fqn}.detection_hits` (hit_time, detection_id, severity, entity, summary, details)
      SELECT CURRENT_TIMESTAMP(), '${each.key}', t.severity, t.entity, t.summary, TO_JSON(t)
      FROM (
      ${templatefile("${local.pack}/detections/bigquery/${each.value.file}", local.sql_vars)}
      ) AS t
      WHERE NOT EXISTS (
        SELECT 1 FROM `${local.register_fqn}.detection_hits` AS h
        WHERE h.detection_id = '${each.key}' AND h.entity = t.entity
          AND h.hit_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL ${each.value.suppress_hours} HOUR)
      )
    SQL
  }
  depends_on = [google_bigquery_table.detection_hits, google_bigquery_table.v_ai_service_accounts]
}

resource "google_bigquery_data_transfer_config" "pb2_pending" {
  display_name         = "yuma-gai-pb2-pending-decisions"
  location             = var.bq_location
  data_source_id       = "scheduled_query"
  schedule             = "every 1 hours"
  service_account_name = google_service_account.detections.email
  params = {
    query = templatefile("${local.pack}/register/sql/pb2_pending_decisions.sql", local.sql_vars)
  }
  depends_on = [google_bigquery_table.detection_hits, google_bigquery_table.ai_agent_register]
}

# --- Near-real-time path for G06 / G07: org sink -> Pub/Sub -> Eventarc -> PB1 workflow ---
resource "google_pubsub_topic" "ai_identity_changes" {
  name = "yuma-gai-ai-identity-changes"
}

resource "google_logging_organization_sink" "ai_identity_changes" {
  name             = "yuma-gai-ai-identity-changes"
  org_id           = var.org_id
  include_children = true
  destination      = "pubsub.googleapis.com/${google_pubsub_topic.ai_identity_changes.id}"
  filter           = <<-EOT
    log_id("cloudaudit.googleapis.com/activity") AND severity!="ERROR" AND (
      protoPayload.methodName=("google.iam.admin.v1.CreateServiceAccountKey" OR "google.iam.admin.v1.UploadServiceAccountKey")
      OR (
        protoPayload.methodName:"SetIamPolicy"
        AND protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD"
        AND protoPayload.serviceData.policyDelta.bindingDeltas.member=~"agents.global.|gcp-sa-aiplatform|gcp-sa-discoveryengine"
      )
    )
  EOT
}

resource "google_pubsub_topic_iam_member" "sink_publisher" {
  topic  = google_pubsub_topic.ai_identity_changes.name
  role   = "roles/pubsub.publisher"
  member = google_logging_organization_sink.ai_identity_changes.writer_identity
}

# AI agent register, detection hits, lookup tables and ISM views (BigQuery).
locals {
  register_fqn = "${var.project_id}.${var.register_dataset_id}"
  sql_vars = {
    logs_table               = var.logs_table
    workspace_activity_table = var.workspace_activity_table
    register_dataset         = local.register_fqn
  }
  pack = "${path.module}/../.."

  ism_rows = csvdecode(file("${local.pack}/register/ism_control_map.csv"))
  ism_map_sql = join("\nUNION ALL\n", [
    for r in local.ism_rows : format("SELECT '%s' AS control_id, '%s' AS control_text, '%s' AS theme, '%s' AS pack_evidence, '%s' AS evidence_method",
    r.control_id, replace(r.control_text, "'", "\\'"), r.theme, replace(r.pack_evidence, "'", "\\'"), r.evidence_method)
  ])
}

resource "google_bigquery_dataset" "register" {
  dataset_id  = var.register_dataset_id
  location    = var.bq_location
  description = "AI agent register, detection hits and ISM AI-control evidence views"
}

resource "google_bigquery_table" "ai_agent_register" {
  dataset_id          = google_bigquery_dataset.register.dataset_id
  table_id            = "ai_agent_register"
  schema              = file("${local.pack}/register/ai_agent_register.schema.json")
  deletion_protection = true
  time_partitioning {
    type  = "MONTH"
    field = "record_time"
  }
}

resource "google_bigquery_table" "detection_hits" {
  dataset_id          = google_bigquery_dataset.register.dataset_id
  table_id            = "detection_hits"
  schema              = file("${local.pack}/register/detection_hits.schema.json")
  deletion_protection = true
  time_partitioning {
    type  = "DAY"
    field = "hit_time"
  }
}

resource "google_bigquery_table" "approved_apps" {
  dataset_id          = google_bigquery_dataset.register.dataset_id
  table_id            = "approved_apps"
  schema              = file("${local.pack}/register/approved_apps.schema.json")
  deletion_protection = false
}

resource "google_bigquery_table" "lookups" {
  for_each = {
    gemini_approved_users = jsonencode([{ name = "email", type = "STRING" }])
    ai_approved_workloads = jsonencode([{ name = "vm_instance_name", type = "STRING" }])
    ai_vendor_cidrs = jsonencode([
      { name = "vendor", type = "STRING" }, { name = "cidr", type = "STRING" },
      { name = "network", type = "STRING" }, { name = "prefix", type = "INT64" }
    ])
  }
  dataset_id          = google_bigquery_dataset.register.dataset_id
  table_id            = each.key
  schema              = each.value
  deletion_protection = false
}

resource "google_bigquery_table" "ism_control_map" {
  dataset_id          = google_bigquery_dataset.register.dataset_id
  table_id            = "ism_control_map"
  deletion_protection = false
  view {
    query          = local.ism_map_sql
    use_legacy_sql = false
  }
}

resource "google_bigquery_table" "v_register_current" {
  dataset_id          = google_bigquery_dataset.register.dataset_id
  table_id            = "v_register_current"
  deletion_protection = false
  view {
    query          = templatefile("${local.pack}/register/sql/v_register_current.sql", local.sql_vars)
    use_legacy_sql = false
  }
  depends_on = [google_bigquery_table.ai_agent_register]
}

resource "google_bigquery_table" "v_ai_service_accounts" {
  dataset_id          = google_bigquery_dataset.register.dataset_id
  table_id            = "v_ai_service_accounts"
  deletion_protection = false
  view {
    query          = templatefile("${local.pack}/register/sql/v_ai_service_accounts.sql", local.sql_vars)
    use_legacy_sql = false
  }
  depends_on = [google_bigquery_table.v_register_current]
}

resource "google_bigquery_table" "v_ism_control_status" {
  dataset_id          = google_bigquery_dataset.register.dataset_id
  table_id            = "v_ism_control_status"
  deletion_protection = false
  view {
    query          = templatefile("${local.pack}/register/sql/v_ism_control_status.sql", local.sql_vars)
    use_legacy_sql = false
  }
  depends_on = [google_bigquery_table.v_register_current, google_bigquery_table.ism_control_map, google_bigquery_table.detection_hits]
}

resource "google_bigquery_table" "v_evidence_summary_md" {
  dataset_id          = google_bigquery_dataset.register.dataset_id
  table_id            = "v_evidence_summary_md"
  deletion_protection = false
  view {
    query          = templatefile("${local.pack}/register/sql/v_evidence_summary_md.sql", local.sql_vars)
    use_legacy_sql = false
  }
  depends_on = [google_bigquery_table.v_ism_control_status]
}

resource "google_bigquery_routine" "sp_workspace_oauth_snapshot" {
  dataset_id      = google_bigquery_dataset.register.dataset_id
  routine_id      = "sp_workspace_oauth_snapshot"
  routine_type    = "PROCEDURE"
  language        = "SQL"
  definition_body = templatefile("${local.pack}/register/sql/sp_workspace_oauth_snapshot.sql", local.sql_vars)
  depends_on      = [google_bigquery_table.ai_agent_register]
}

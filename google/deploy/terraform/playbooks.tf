# Playbooks without Google SecOps: Workflows + Eventarc + Cloud Scheduler + Cloud Run functions.
locals {
  functions = {
    approval           = { entry = "approve", ingress = "ALLOW_ALL" } # put behind IAP (see playbooks/PB1)
    revoke_oauth_token = { entry = "revoke", ingress = "ALLOW_INTERNAL_ONLY" }
    ti_enrich_block    = { entry = "handler", ingress = "ALLOW_INTERNAL_ONLY" }
  }
}

# ---------- service accounts ----------
resource "google_service_account" "sa" {
  for_each     = toset(["pb1", "pb4", "pb5", "eventarc", "scheduler", "fn-approval", "fn-revoke", "fn-ti"])
  account_id   = "yuma-gai-${each.key}"
  display_name = "AI pack ${each.key}"
}

# ---------- secrets (values are added out of band; never in Terraform state) ----------
resource "google_secret_manager_secret" "s" {
  for_each  = toset(["yuma-gai-chat-webhook", "yuma-gai-abuseipdb-key", "yuma-gai-threatfox-key", "yuma-gai-greynoise-key"])
  secret_id = each.key
  replication {
    auto {}
  }
}

# ---------- function source ----------
resource "google_storage_bucket" "fn_src" {
  name                        = "${var.project_id}-yuma-gai-fn-src"
  location                    = var.region
  uniform_bucket_level_access = true
}

data "archive_file" "fn" {
  for_each    = local.functions
  type        = "zip"
  source_dir  = "${local.pack}/functions/${each.key}"
  output_path = "${path.module}/.build/${each.key}.zip"
}

resource "google_storage_bucket_object" "fn" {
  for_each = local.functions
  name     = "${each.key}-${data.archive_file.fn[each.key].output_md5}.zip"
  bucket   = google_storage_bucket.fn_src.name
  source   = data.archive_file.fn[each.key].output_path
}

resource "google_cloudfunctions2_function" "fn" {
  for_each = local.functions
  name     = "yuma-gai-${replace(each.key, "_", "-")}"
  location = var.region

  build_config {
    runtime     = "python312"
    entry_point = each.value.entry
    source {
      storage_source {
        bucket = google_storage_bucket.fn_src.name
        object = google_storage_bucket_object.fn[each.key].name
      }
    }
  }

  service_config {
    max_instance_count    = 2
    timeout_seconds       = 300
    ingress_settings      = each.value.ingress
    service_account_email = google_service_account.sa[each.key == "approval" ? "fn-approval" : each.key == "revoke_oauth_token" ? "fn-revoke" : "fn-ti"].email
    environment_variables = each.key == "approval" ? {
      IAP_AUDIENCE = var.approver_iap_audience
      } : each.key == "revoke_oauth_token" ? {
      FUNCTION_SA_EMAIL = google_service_account.sa["fn-revoke"].email
      ADMIN_SUBJECT     = var.workspace_admin_subject
      } : {
      POLICY_PROJECT   = var.project_id
      SECURITY_POLICY  = var.security_policy_name
      REGISTER_DATASET = local.register_fqn
      ALLOWLIST_CIDRS  = var.ti_allowlist_cidrs
      BLOCK_TTL_HOURS  = "24"
    }

    dynamic "secret_environment_variables" {
      for_each = each.key == "ti_enrich_block" ? {
        ABUSEIPDB_KEY = "yuma-gai-abuseipdb-key"
        THREATFOX_KEY = "yuma-gai-threatfox-key"
        GREYNOISE_KEY = "yuma-gai-greynoise-key"
      } : {}
      content {
        key        = secret_environment_variables.key
        project_id = var.project_id
        secret     = google_secret_manager_secret.s[secret_environment_variables.value].secret_id
        version    = "latest"
      }
    }
  }
}

# ---------- workflows ----------
resource "google_workflows_workflow" "pb1" {
  name            = "yuma-gai-pb1-containment"
  region          = var.region
  service_account = google_service_account.sa["pb1"].id
  source_contents = file("${local.pack}/workflows/pb1-containment.yaml")
  user_env_vars = {
    REGISTER_DATASET    = local.register_fqn
    APPROVAL_URL        = var.approval_url
    CHAT_WEBHOOK_SECRET = google_secret_manager_secret.s["yuma-gai-chat-webhook"].secret_id
    REVOKE_FN_URL       = google_cloudfunctions2_function.fn["revoke_oauth_token"].service_config[0].uri
    APPROVAL_TIMEOUT_S  = "3600"
  }
}

resource "google_workflows_workflow" "pb4" {
  name            = "yuma-gai-pb4-inventory-sync"
  region          = var.region
  service_account = google_service_account.sa["pb4"].id
  source_contents = file("${local.pack}/workflows/pb4-inventory-sync.yaml")
  user_env_vars = {
    ORG_ID           = var.org_id
    REGISTER_DATASET = local.register_fqn
  }
}

resource "google_workflows_workflow" "pb5" {
  name            = "yuma-gai-pb5-evidence-export"
  region          = var.region
  service_account = google_service_account.sa["pb5"].id
  source_contents = file("${local.pack}/workflows/pb5-evidence-export.yaml")
  user_env_vars = {
    REGISTER_DATASET = local.register_fqn
    EVIDENCE_BUCKET  = google_storage_bucket.evidence.name
  }
}

# ---------- PB1 trigger: Pub/Sub (org sink) -> Eventarc -> workflow ----------
resource "google_eventarc_trigger" "pb1" {
  name            = "yuma-gai-pb1-ai-identity-changes"
  location        = var.region
  service_account = google_service_account.sa["eventarc"].email
  matching_criteria {
    attribute = "type"
    value     = "google.cloud.pubsub.topic.v1.messagePublished"
  }
  transport {
    pubsub {
      topic = google_pubsub_topic.ai_identity_changes.id
    }
  }
  destination {
    workflow = google_workflows_workflow.pb1.id
  }
}

# ---------- schedules (Australia/Sydney) ----------
resource "google_cloud_scheduler_job" "workflow" {
  for_each = {
    pb4 = { schedule = "15 2 * * *", wf = google_workflows_workflow.pb4.id }
    pb5 = { schedule = "0 6 1 * *", wf = google_workflows_workflow.pb5.id }
  }
  name      = "yuma-gai-${each.key}"
  region    = var.region
  schedule  = each.value.schedule
  time_zone = "Australia/Sydney"
  http_target {
    http_method = "POST"
    uri         = "https://workflowexecutions.googleapis.com/v1/${each.value.wf}/executions"
    body        = base64encode(jsonencode({ argument = jsonencode({}) }))
    oauth_token {
      service_account_email = google_service_account.sa["scheduler"].email
      scope                 = "https://www.googleapis.com/auth/cloud-platform"
    }
  }
}

resource "google_cloud_scheduler_job" "pb3" {
  for_each  = { enrich_block = "*/10 * * * *", cleanup = "5 * * * *" }
  name      = "yuma-gai-pb3-${replace(each.key, "_", "-")}"
  region    = var.region
  schedule  = each.value
  time_zone = "Australia/Sydney"
  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.fn["ti_enrich_block"].service_config[0].uri
    body        = base64encode(jsonencode({ mode = each.key }))
    headers     = { "Content-Type" = "application/json" }
    oidc_token {
      service_account_email = google_service_account.sa["scheduler"].email
    }
  }
}

# ---------- evidence bucket ----------
resource "google_storage_bucket" "evidence" {
  name                        = var.evidence_bucket_name
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  versioning {
    enabled = true
  }
  retention_policy {
    retention_period = var.evidence_retention_days * 86400
    is_locked        = false # lock manually after sign-off; locking is irreversible
  }
}

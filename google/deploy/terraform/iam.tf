# Least-privilege-ish IAM for the playbooks. Items marked HIGH-RISK are powerful by nature: put them in the AI agent
# register themselves, alert on their use, and keep PB1's human approval step.

# PB1: disable service accounts / keys and roll back project IAM grants, across the org. HIGH-RISK.
resource "google_organization_iam_member" "pb1_org" {
  for_each = toset([
    "roles/iam.serviceAccountAdmin",         # serviceAccounts.disable
    "roles/iam.serviceAccountKeyAdmin",      # keys.disable
    "roles/resourcemanager.projectIamAdmin", # projects get/setIamPolicy
  ])
  org_id = var.org_id
  role   = each.value
  member = google_service_account.sa["pb1"].member
}

# PB4: read AI resources across the org.
resource "google_organization_iam_member" "pb4_org" {
  for_each = toset(["roles/cloudasset.viewer", "roles/aiplatform.viewer", "roles/discoveryengine.viewer"])
  org_id   = var.org_id
  role     = each.value
  member   = google_service_account.sa["pb4"].member
}

resource "google_project_iam_member" "bq_jobuser" {
  for_each = toset(["pb1", "pb4", "pb5", "fn-ti"])
  project  = var.project_id
  role     = "roles/bigquery.jobUser"
  member   = google_service_account.sa[each.key].member
}

resource "google_bigquery_dataset_iam_member" "register_rw" {
  for_each   = toset(["pb1", "pb4"])
  dataset_id = google_bigquery_dataset.register.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = google_service_account.sa[each.key].member
}

resource "google_bigquery_dataset_iam_member" "register_ro" {
  for_each   = toset(["pb5", "fn-ti"])
  dataset_id = google_bigquery_dataset.register.dataset_id
  role       = "roles/bigquery.dataViewer"
  member     = google_service_account.sa[each.key].member
}

# PB4 calls the stored procedure, which reads the Workspace export. Narrow to that dataset in production.
resource "google_project_iam_member" "pb4_workspace_read" {
  project = var.project_id
  role    = "roles/bigquery.dataViewer"
  member  = google_service_account.sa["pb4"].member
}

resource "google_storage_bucket_iam_member" "pb5_evidence" {
  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectCreator"
  member = google_service_account.sa["pb5"].member
}

resource "google_secret_manager_secret_iam_member" "pb1_chat" {
  secret_id = google_secret_manager_secret.s["yuma-gai-chat-webhook"].id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.sa["pb1"].member
}

resource "google_secret_manager_secret_iam_member" "ti_keys" {
  for_each  = toset(["yuma-gai-abuseipdb-key", "yuma-gai-threatfox-key", "yuma-gai-greynoise-key"])
  secret_id = google_secret_manager_secret.s[each.key].id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.sa["fn-ti"].member
}

# PB3 edits the Cloud Armor policy. HIGH-RISK (can block traffic); rules are tagged, banded and expire.
resource "google_project_iam_member" "ti_armor" {
  project = var.project_id
  role    = "roles/compute.securityAdmin"
  member  = google_service_account.sa["fn-ti"].member
}

# Keyless domain-wide delegation: the revoke function signs its own JWT. HIGH-RISK (Workspace admin delegation).
resource "google_service_account_iam_member" "revoke_self_sign" {
  service_account_id = google_service_account.sa["fn-revoke"].name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = google_service_account.sa["fn-revoke"].member
}

# Invocations
resource "google_cloud_run_service_iam_member" "pb1_invokes_revoke" {
  location = var.region
  service  = google_cloudfunctions2_function.fn["revoke_oauth_token"].name
  role     = "roles/run.invoker"
  member   = google_service_account.sa["pb1"].member
}

resource "google_cloud_run_service_iam_member" "scheduler_invokes_ti" {
  location = var.region
  service  = google_cloudfunctions2_function.fn["ti_enrich_block"].name
  role     = "roles/run.invoker"
  member   = google_service_account.sa["scheduler"].member
}

resource "google_project_iam_member" "workflow_invokers" {
  for_each = toset(["eventarc", "scheduler", "fn-approval"]) # fn-approval needs workflows.callbacks.send
  project  = var.project_id
  role     = "roles/workflows.invoker"
  member   = google_service_account.sa[each.key].member
}

resource "google_project_iam_member" "eventarc_receiver" {
  project = var.project_id
  role    = "roles/eventarc.eventReceiver"
  member  = google_service_account.sa["eventarc"].member
}

resource "google_project_iam_member" "workflow_logging" {
  for_each = toset(["pb1", "pb4", "pb5"])
  project  = var.project_id
  role     = "roles/logging.logWriter"
  member   = google_service_account.sa[each.key].member
}

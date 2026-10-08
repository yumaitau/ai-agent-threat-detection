variable "project_id" {
  description = "Security tooling project that hosts the register, workflows and functions"
  type        = string
}

variable "region" {
  description = "Region for Workflows, Cloud Run functions, Eventarc and Scheduler"
  type        = string
  default     = "australia-southeast1"
}

variable "bq_location" {
  description = "BigQuery location; must match the Log Analytics linked dataset and the Workspace export dataset"
  type        = string
  default     = "australia-southeast1"
}

variable "org_id" {
  description = "Google Cloud organization ID (numeric)"
  type        = string
}

variable "logs_table" {
  description = "Log Analytics _AllLogs view, e.g. my-proj.my_linked_dataset._AllLogs (org aggregated log bucket upgraded to Log Analytics, with a linked BigQuery dataset)"
  type        = string
}

variable "workspace_activity_table" {
  description = "Google Workspace BigQuery export activity table, e.g. my-proj.workspace_logs.activity"
  type        = string
}

variable "register_dataset_id" {
  description = "Dataset for the AI agent register, detection hits and ISM views"
  type        = string
  default     = "yuma_ai_register"
}

variable "evidence_bucket_name" {
  description = "Globally unique bucket name for monthly ISM evidence"
  type        = string
}

variable "evidence_retention_days" {
  description = "Retention policy on the evidence bucket (lock it manually once agreed)"
  type        = number
  default     = 2557 # 7 years
}

variable "security_policy_name" {
  description = "Existing Cloud Armor backend security policy that PB3 adds deny rules to"
  type        = string
}

variable "workspace_admin_subject" {
  description = "Dedicated Workspace admin user (custom role: user security management only) that the revoke function impersonates through domain-wide delegation"
  type        = string
}

variable "approver_iap_audience" {
  description = "IAP audience string for the approval service (set after you put it behind IAP)"
  type        = string
  default     = ""
}

variable "approval_url" {
  description = "HTTPS URL of the approval service behind IAP (set after IAP is configured)"
  type        = string
  default     = "https://approval.example.invalid/"
}

variable "enable_hunts" {
  description = "Also schedule the hunt-grade queries (G02, G05, G09-G12, G14, G15) daily"
  type        = bool
  default     = false
}

variable "ti_allowlist_cidrs" {
  description = "Comma-separated CIDRs PB3 must never block (your egress, partners, monitoring)"
  type        = string
  default     = ""
}

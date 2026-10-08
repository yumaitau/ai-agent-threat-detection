output "register_dataset" {
  value = local.register_fqn
}

output "pb1_workflow" {
  value = google_workflows_workflow.pb1.id
}

output "approval_function_uri" {
  value = google_cloudfunctions2_function.fn["approval"].service_config[0].uri
}

output "org_sink_writer_identity" {
  value = google_logging_organization_sink.ai_identity_changes.writer_identity
}

output "scheduled_detections" {
  value = keys(local.scheduled)
}

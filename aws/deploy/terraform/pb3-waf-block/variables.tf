variable "region" {
  type    = string
  default = "ap-southeast-2"
}

variable "waf_scope" {
  type        = string
  default     = "REGIONAL"
  description = "REGIONAL (ALB, API Gateway, AppSync, Cognito, App Runner, Verified Access) or CLOUDFRONT (deploy in us-east-1)"
  validation {
    condition     = contains(["REGIONAL", "CLOUDFRONT"], var.waf_scope)
    error_message = "waf_scope must be REGIONAL or CLOUDFRONT."
  }
}

variable "waf_log_group_name" {
  type        = string
  description = "CloudWatch Logs group receiving WAF logs (name must start with aws-waf-logs-)"
}

variable "register_table_arn" {
  type        = string
  description = "ARN of the YumaAIAgentRegister table from the core CloudFormation stack"
}

variable "artifact_bucket" {
  type = string
}

variable "artifact_prefix" {
  type    = string
  default = "yuma-aia/0.1.0/"
}

variable "threat_intel_secret_arn" {
  type        = string
  default     = ""
  description = "Optional Secrets Manager secret ARN with {\"abuseipdb\": \"...\", \"threatfox\": \"...\"}"
}

variable "auto_block" {
  type        = bool
  default     = false
  description = "false = propose only (results in the Lambda output and register); true = update the IP set"
}

variable "block_score" {
  type    = number
  default = 60
}

variable "block_hours" {
  type    = number
  default = 24
}

variable "allow_cidrs" {
  type        = list(string)
  default     = []
  description = "Never block these (your scanners, monitoring, partners)"
}

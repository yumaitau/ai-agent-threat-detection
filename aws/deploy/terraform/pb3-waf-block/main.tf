# Yuma AIA PB3: AI-speed exploitation burst -> threat intel enrichment -> WAF IP set block with expiry.
# DRAFT skeleton. Validated offline with `terraform validate` only; not applied anywhere.
terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

resource "aws_wafv2_ip_set" "block" {
  name               = "yuma-aia-pb3-block"
  description        = "IPs blocked by Yuma AIA PB3 (entries expire; managed by Lambda)"
  scope              = var.waf_scope
  ip_address_version = "IPV4"
  addresses          = []

  lifecycle {
    ignore_changes = [addresses] # the Lambda owns the address list
  }
}

# Rule group the customer adds to their web ACL (rule group reference statement), ahead of other rules.
resource "aws_wafv2_rule_group" "block" {
  name     = "yuma-aia-pb3"
  scope    = var.waf_scope
  capacity = 5

  rule {
    name     = "block-pb3-ipset"
    priority = 0
    action {
      block {}
    }
    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.block.arn
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "yuma-aia-pb3-block"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "yuma-aia-pb3"
    sampled_requests_enabled   = true
  }
}

resource "aws_iam_role" "pb3" {
  name = "yuma-aia-pb3"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "pb3_basic" {
  role       = aws_iam_role.pb3.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "pb3" {
  name = "pb3"
  role = aws_iam_role.pb3.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      { Effect = "Allow", Action = ["logs:StartQuery", "logs:GetQueryResults"], Resource = "*" },
      { Effect = "Allow", Action = ["wafv2:GetIPSet", "wafv2:UpdateIPSet"], Resource = aws_wafv2_ip_set.block.arn },
      { Effect = "Allow", Action = ["dynamodb:PutItem", "dynamodb:Query", "dynamodb:DeleteItem"], Resource = var.register_table_arn }
      ], var.threat_intel_secret_arn == "" ? [] : [
      { Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = var.threat_intel_secret_arn }
    ])
  })
}

resource "aws_lambda_function" "pb3" {
  function_name = "yuma-aia-pb3-waf-block"
  role          = aws_iam_role.pb3.arn
  runtime       = "python3.12"
  handler       = "pb3_waf_block.handler"
  s3_bucket     = var.artifact_bucket
  s3_key        = "${var.artifact_prefix}lambda/pb3_waf_block.zip"
  timeout       = 300
  memory_size   = 256

  environment {
    variables = {
      REGISTER_TABLE         = element(split("/", var.register_table_arn), 1)
      WAF_LOG_GROUP          = var.waf_log_group_name
      IPSET_NAME             = aws_wafv2_ip_set.block.name
      IPSET_ID               = aws_wafv2_ip_set.block.id
      IPSET_SCOPE            = var.waf_scope
      AUTO_BLOCK             = tostring(var.auto_block)
      BLOCK_SCORE            = tostring(var.block_score)
      BLOCK_HOURS            = tostring(var.block_hours)
      ALLOW_CIDRS            = join(",", var.allow_cidrs)
      THREAT_INTEL_SECRET_ID = var.threat_intel_secret_arn
    }
  }
}

resource "aws_iam_role" "scheduler" {
  name = "yuma-aia-pb3-scheduler"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "scheduler.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "scheduler" {
  name = "invoke-pb3"
  role = aws_iam_role.scheduler.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "lambda:InvokeFunction", Resource = aws_lambda_function.pb3.arn }]
  })
}

resource "aws_scheduler_schedule" "pb3" {
  name                = "yuma-aia-pb3-every-15-min"
  schedule_expression = "rate(15 minutes)"
  flexible_time_window {
    mode = "OFF"
  }
  target {
    arn      = aws_lambda_function.pb3.arn
    role_arn = aws_iam_role.scheduler.arn
    input    = jsonencode({})
  }
}

output "ip_set_arn" {
  value = aws_wafv2_ip_set.block.arn
}

output "rule_group_arn" {
  value = aws_wafv2_rule_group.block.arn
}

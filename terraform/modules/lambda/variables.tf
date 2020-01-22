// Until Terraform supports "count" for modules (https://github.com/hashicorp/terraform/issues/953),
// the count (0 or 1) needs to be passed to each individual resource.
variable "enabled" {
  description = "1 to enable the module (default); set to 0 to disable"
  default     = 1
}

variable "function_name" {
  description = "Name of the Lambda function"
}

variable "description" {
  description = "Lambda function description"
}

variable "base_policy_arn" {
  description = "ARN for the base policy attached to all Lambda functions"
}

variable "handler" {
  description = "Entry point for the Lambda code (e.g. 'main.handler' invokes main.py:handler())"
}

variable "memory_size_mb" {
  description = <<EOF
Memory allocated to the Lambda function (128 - 1536 MB).
Lambda also allocates CPU and network resources in proportion to the configured memory.
EOF

}

variable "timeout_sec" {
  description = "Maximum duration for the Lambda function (up to 300 seconds)"
}

variable "filename" {
  description = "Name of the .zip file containing the Lambda deployment package"
}

variable "reserved_concurrent_executions" {
  description = "Reserved concurrency limit for this Lambda function"
}

variable "environment_variables" {
  type        = map(string)
  description = "Map of environment variables available to the running Lambda function"
}

variable "log_retention_days" {
  description = "Number of days to retain Lambda execution logs in CloudWatch"
}

variable "tagged_name" {
  description = "The 'Name' tag on CloudWatch logs and Lambda will be set to this value"
}

variable "alarm_errors_help" {
  description = "Function-specific context for the error alarm description"
  default     = ""
}

variable "alarm_errors_threshold" {
  description = "If at least this many errors occur within alarm_errors_interval_secs, a metric alarm will trigger"

  # The error threshold has been increased significantly; this is due to a recent change that
  # retries HTTP 404s by raising errors on Lambda, designed to accommodate for race conditions
  # on the availability of the binary resource.
  default = 250
}

variable "alarm_errors_interval_secs" {
  description = "Sliding interval (seconds) in which to count errors"
  default     = 300
}

variable "alarm_sns_arns" {
  type        = list(string)
  description = "A list of SNS topic ARNs which will be notified when a metric alarm triggers"
}


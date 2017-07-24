variable "function_name" {}
variable "description" {}
variable "base_policy_arn" {}
variable "handler" {}
variable "memory_size_mb" {}
variable "timeout_sec" {}
variable "filename" {}

variable "environment_variables" {
  type = "map"
}

variable "log_retention_days" {}

// Add function-specific context to the error alarm description.
variable "alarm_errors_help" {
  default = ""
}

// If "threshold" or more errors occur in "interval", a metric alarm will trigger.
variable "alarm_errors_threshold" {
  default = 1
}

variable "alarm_errors_interval_secs" {
  default = 300 // 5 minutes
}

// A list of SNS topic ARNs which will be notified if a metric alarm triggers.
variable "alarm_sns_arns" {
  type = "list"
}

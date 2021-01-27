/* See terraform.tfvars for descriptions of each of the variables. */

variable "aws_account_id" {
  type        = string
  description = "12-digit AWS account ID"
}

variable "aws_account_name" {
  type        = string
  description = "AWS account name, last part of the ARN, right after the ':' (colon), for instance 'root', or 'user/thename'"
}

variable "aws_region" {
  type        = string
  description = "AWS region in which to deploy the BinaryAlert components"
}

variable "name_prefix" {
  type        = string
  description = "Prefix used in all resource names (required for uniqueness) E.g. 'company_team'"
}

variable "enable_carbon_black_downloader" {
  type        = bool
  description = "Whether to enable CarbonBlack Downloader resources"
}

variable "carbon_black_url" {
  type        = string
  description = "URL of the CarbonBlack server"
}

variable "carbon_black_timeout" {
  type        = number
  description = "Timeout to use for Carbon Black API client. The client default is 60, so set to something lower if desired"
}

variable "encrypted_carbon_black_api_token" {
  type        = string
  description = "Encrypted API token used to interface with CarbonBlack"
}

variable "s3_log_bucket" {
  type        = string
  description = "Pre-existing bucket in which to store S3 access logs. If not specified, one will be created"
}

variable "s3_log_prefix" {
  type        = string
  description = "Log files will be stored in S3 with this prefix"
}

variable "s3_log_expiration_days" {
  type        = number
  description = "Access logs expire after this many days. Has no effect if using pre-existing bucket for logs"
}

variable "lambda_log_retention_days" {
  type        = number
  description = "How long to retain Lambda function logs for in days"
}

variable "tagged_name" {
  type        = string
  description = "Assigns this as the value for tag key 'Name' for all supported resources (CloudWatch logs, Dynamo, KMS, Lambda, S3, SQS)"
}

variable "metric_alarm_sns_topic_arn" {
  type        = string
  description = "Use an existing SNS topic for metric alarms (instead of creating one automatically)"
}

variable "expected_analysis_frequency_minutes" {
  type        = number
  description = "Alarm if no binaries are analyzed for this amount of time"
}

variable "dynamo_read_capacity" {
  type        = number
  description = "Provisioned read capacity for the Dynamo table which stores match results"
}

variable "dynamo_write_capacity" {
  type        = number
  description = "Provisioned write capacity for the Dynamo table which stores match results"
}

variable "lambda_analyze_memory_mb" {
  type        = number
  description = "Memory limit for the analyzer function"
}

variable "lambda_analyze_timeout_sec" {
  type        = number
  description = "Time limit for the analyzer function"
}

variable "lambda_analyze_concurrency_limit" {
  type        = number
  description = "Concurrency limit for the analyzer function"
}

variable "lambda_download_memory_mb" {
  type        = number
  description = "Memory limit for the downloader function"
}

variable "lambda_download_timeout_sec" {
  type        = number
  description = "Time limit for the downloader function"
}

variable "lambda_download_concurrency_limit" {
  type        = number
  description = "Concurrency limit for the downloader function"
}

variable "force_destroy" {
  type        = bool
  description = "WARNING: If force destroy is enabled, all objects in the S3 bucket(s) will be deleted during"
}

variable "external_s3_bucket_resources" {
  type        = list(string)
  description = "Grants appropriate S3 bucket permissions to the analyzer function if you are using BinaryAlert to scan existing S3 buckets"
}

variable "external_kms_key_resources" {
  type        = list(string)
  description = "Grants appropriate KMS permissions to the analyzer function if you are using BinaryAlert to scan existing S3 buckets"
}

variable "enable_negative_match_alerts" {
  type        = bool
  description = "Create a separate SNS topic which reports files that do NOT match any YARA rules"
}

variable "analyze_queue_batch_size" {
  type        = number
  description = "Maximum number of messages that will be received by each invocation of the analyzer function"
}

variable "download_queue_batch_size" {
  type        = number
  description = "Maximum number of messages that will be received by each invocation of the downloader function"
}

variable "analyze_queue_retention_secs" {
  type        = number
  description = "Messages in the analyzer queue will be retained and retried for the specified duration until expiring"
}

variable "download_queue_retention_secs" {
  type        = number
  description = "Messages in the downloader queue will be retained and retried for the specified duration until expiring"
}

variable "objects_per_retro_message" {
  type        = number
  description = "During a retroactive scan, number of S3 objects to pack into a single SQS message"
}

variable "download_queue_max_receives" {
  type        = number
  description = "Number of times a download SQS message is attempted to be delivered successfully before being moved to the DLQ"
}


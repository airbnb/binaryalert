/* See terraform.tfvars for descriptions of each of the variables. */

variable "aws_account_id" {
}

variable "aws_region" {
}

variable "name_prefix" {
}

variable "enable_carbon_black_downloader" {
}

variable "carbon_black_url" {
}

variable "carbon_black_timeout" {
}

variable "encrypted_carbon_black_api_token" {
}

variable "s3_log_bucket" {
}

variable "s3_log_prefix" {
}

variable "s3_log_expiration_days" {
}

variable "lambda_log_retention_days" {
}

variable "tagged_name" {
}

variable "metric_alarm_sns_topic_arn" {
}

variable "expected_analysis_frequency_minutes" {
}

variable "dynamo_read_capacity" {
}

variable "dynamo_write_capacity" {
}

variable "lambda_analyze_memory_mb" {
}

variable "lambda_analyze_timeout_sec" {
}

variable "lambda_analyze_concurrency_limit" {
}

variable "lambda_download_memory_mb" {
}

variable "lambda_download_timeout_sec" {
}

variable "lambda_download_concurrency_limit" {
}

variable "force_destroy" {
}

variable "external_s3_bucket_resources" {
  type = list(string)
}

variable "external_kms_key_resources" {
  type = list(string)
}

variable "enable_negative_match_alerts" {
}

variable "analyze_queue_batch_size" {
}

variable "download_queue_batch_size" {
}

variable "analyze_queue_retention_secs" {
}

variable "download_queue_retention_secs" {
}

variable "objects_per_retro_message" {
}

variable "download_queue_max_receives" {
}


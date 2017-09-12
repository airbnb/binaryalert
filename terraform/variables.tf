/* See terraform.tfvars for descriptions of each of the variables. */

variable "aws_region" {}
variable "name_prefix" {}

variable "enable_carbon_black_downloader" {}
variable "carbon_black_url" {}
variable "encrypted_carbon_black_api_token" {}

variable "s3_log_bucket" {}
variable "s3_log_prefix" {}
variable "s3_log_expiration_days" {}
variable "lambda_log_retention_days" {}

variable "sqs_retention_minutes" {}
variable "lambda_batch_objects_per_message" {}
variable "lambda_batch_memory_mb" {}
variable "lambda_dispatch_frequency_minutes" {}
variable "lambda_dispatch_limit" {}
variable "lambda_dispatch_memory_mb" {}
variable "lambda_dispatch_timeout_sec" {}
variable "lambda_analyze_memory_mb" {}
variable "lambda_analyze_timeout_sec" {}
variable "lambda_download_memory_mb" {}
variable "lambda_download_timeout_sec" {}
variable "expected_analysis_frequency_minutes" {}
variable "dynamo_read_capacity" {}
variable "dynamo_write_capacity" {}

/* BinaryAlert configuration. */
// Auto-Configured sections are managed with "python3 ../manage.py configure"
// Other (advanced) configuration can be updated directly in this file.

/* ********** [Auto-Configured] Base Configuration ********** */
// These are the only settings you need to get started.

// 12-digit AWS account ID
aws_account_id = ""

// AWS region in which to deploy the BinaryAlert components.
aws_region = "us-east-1"

// Prefix used in all resource names (required for uniqueness). E.g. "company_team"
name_prefix = ""

/* ********** [Auto-Configured] Optional CarbonBlack Downloader ********** */
enable_carbon_black_downloader = false

// URL of the CarbonBlack server.
carbon_black_url = ""

// Timeout to use for Carbon Black API client.
// The client default is 60, so set to something lower if desired.
carbon_black_timeout = 60

// The encrypted CarbonBlack API token will automatically be generated and saved here:
encrypted_carbon_black_api_token = ""

/* ********** Log Retention ********** */
// Pre-existing bucket in which to store S3 access logs. If not specified, one will be created.
s3_log_bucket = ""

// Log files will be stored in S3 with this prefix.
s3_log_prefix = "s3-access-logs/"

// Access logs expire after this many days. Has no effect if using pre-existing bucket for logs.
s3_log_expiration_days = 90

// How long to retain Lambda function logs.
lambda_log_retention_days = 14

/* ********** Advanced Configuration ********** */
// Tags make it easier to organize resources, view grouped billing information, etc.
// All supported resources (CloudWatch logs, Dyanmo, KMS, Lambda, S3, SQS) are tagged with
// Name = [YOUR_VALUE_BELOW]
tagged_name = "BinaryAlert"

// ##### Alarms #####
// Use an existing SNS topic for metric alarms (instead of creating one automatically).
metric_alarm_sns_topic_arn = ""

// Alarm if no binaries are analyzed for this amount of time.
expected_analysis_frequency_minutes = 30

// ##### Dynamo #####
// Provisioned read/write capacity for the Dynamo table which stores match results.
// Capacity is (very roughly) maximum number of operations per second. See Dynamo documentation.
// Since there will likely be very few matches, these numbers can be quite low.
dynamo_read_capacity = 10

dynamo_write_capacity = 5

// ##### Lambda #####
// For reference, here is a simple architectural schematic:
//
//     Download SQS   <<<<< --|
//                            |
// Downloader Lambda  <<<<< --|
//        vv
//        S3
//        vv
//      S3 Events          Analyzer Lambda
//               \        /
//                SQS <<<< Analyzer Lambda
//               /        \
//     Retro Scan          Analyzer Lambda

// Memory, time, and concurrency limits for the analyzer function.
lambda_analyze_memory_mb = 1024

lambda_analyze_timeout_sec = 300

lambda_analyze_concurrency_limit = 100

// Memory, time, and concurrency limits for the downloader function.
lambda_download_memory_mb = 256

lambda_download_timeout_sec = 300

lambda_download_concurrency_limit = 100

// ##### S3 #####
// WARNING: If force destroy is enabled, all objects in the S3 bucket(s) will be deleted during
// `terraform destroy`
force_destroy = true

// If using BinaryAlert to scan existing S3 buckets, add the S3 and KMS resource ARNs here to grant
// the appropriate permissions to the analyzer Lambda function.
external_s3_bucket_resources = []

external_kms_key_resources = []

// ##### SNS #####
// Create a separate SNS topic which reports files that do NOT match any YARA rules.
enable_negative_match_alerts = false

// ##### SQS #####
// Maximum number of messages that will be received by each invocation of the respective function.
analyze_queue_batch_size = 10

download_queue_batch_size = 1

// Messages in the queue will be retained and retried for the specified duration until expiring.
analyze_queue_retention_secs = 86400

download_queue_retention_secs = 86400

// During a retroactive scan, number of S3 objects to pack into a single SQS message.
objects_per_retro_message = 4

// If an SQS message is not deleted (successfully processed) after the max number of receive
// attempts, the message is delivered to the SQS dead-letter queue.
// Retries are common due to race-conditions with binaries landing on the Carbon Black server
download_queue_max_receives = 100

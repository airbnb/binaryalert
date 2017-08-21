/* BinaryAlert configuration. */
// Auto-Configured sections are managed with "python3 ../manage.py configure"
// Other (advanced) configuration can be updated directly in this file.

/* ********** [Auto-Configured] Base Configuration ********** */
// These are the only settings you need to get started.

// AWS region in which to deploy the BinaryAlert components.
aws_region = "us-east-1"

// Prefix used in all resource names (required for uniqueness). E.g. "company_team"
name_prefix = ""


/* ********** [Auto-Configured] Optional CarbonBlack Downloader ********** */
enable_carbon_black_downloader = 0

// URL of the CarbonBlack server.
carbon_black_url = ""

// The encrypted CarbonBlack API token will automatically be generated and saved here:
encrypted_carbon_black_api_token = ""


/* ********** Log Retention ********** */
// Pre-existing bucket in which to store S3 access logs. If not specified, one will be created.
s3_log_bucket = ""

// Log files will be stored in S3 with this prefix.
s3_log_prefix = "s3-access-logs/"

// Access logs expire after this many days. Has no effect if using pre-existing bucket for logs.
s3_log_expiration_days = 60

// How long to retain Lambda function logs.
lambda_log_retention_days = 60


/* ********** Advanced Configuration ********** */
// These settings define the constraints and scale of BinaryAlert components.
// They shouldn't need adjusting unless BinaryAlert needs to scale up (i.e. is hitting resource
// limits). For reference, here is a simple architectural schematic:
//
//     S3 Events                               Analyzer Lambda
//               \                           /
//                SQS <<< Dispatch Lambda >>>  Analyzer Lambda
//               /                           \
//  Batch Lambda                               Analyzer Lambda

// How long messages should be retained in SQS before being dropped.
// Messages will continue to be dispatched to analyzers until they timeout.
sqs_retention_minutes = 60

// Number of S3 object keys to pack into a single SQS message.
// Each downstream analyzer will process at most 10 SQS messages, each with this many objects.
// Higher values allow for higher throughput, but are constrained by analyzer execution time limit.
lambda_batch_objects_per_message = 20

// Memory limit (MB) for the batching Lambda function. 128 is the minimum allowed by Lambda.
lambda_batch_memory_mb = 128

// How often the Lambda dispatcher will be invoked.
// To ensure only one dispatcher is running, this rate should be > the lambda dispatch timeout.
lambda_dispatch_frequency_minutes = 1

// Maximum number of analyzers that can be asynchronously invoked during one dispatcher run.
// Higher values allow for more throughtput, but if too many analyzers are invoked too quickly,
// Lambda invocations may be throttled.
lambda_dispatch_limit = 50

// Memory and time limits for the dispatching function.
lambda_dispatch_memory_mb = 128
lambda_dispatch_timeout_sec = 40

// Memory and time limits for the analyzer functions.
lambda_analyze_memory_mb = 1024
lambda_analyze_timeout_sec = 300

// Memory and time limits for the downloader function.
lambda_download_memory_mb = 128
lambda_download_timeout_sec = 300

// Alarm if no binaries are analyzed for this amount of time.
expected_analysis_frequency_minutes = 30

// Provisioned capacity for the Dynamo table which stores match results.
// Capacity is (very roughly) maximum number of operations per second. See Dynamo documentation.
// Since there will likely be very few matches, these numbers can be quite low.
dynamo_read_capacity = 10
dynamo_write_capacity = 5

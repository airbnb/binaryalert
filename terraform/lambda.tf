// Create the analyzer Lambda function.
module "binaryalert_analyzer" {
  source          = "modules/lambda"
  function_name   = "${var.name_prefix}_binaryalert_analyzer"
  description     = "Analyze a binary with a set of YARA rules"
  base_policy_arn = "${aws_iam_policy.base_policy.arn}"
  handler         = "main.analyze_lambda_handler"
  memory_size_mb  = "${var.lambda_analyze_memory_mb}"
  timeout_sec     = "${var.lambda_analyze_timeout_sec}"
  filename        = "lambda_analyzer.zip"

  environment_variables = {
    YARA_MATCHES_DYNAMO_TABLE_NAME = "${aws_dynamodb_table.binaryalert_yara_matches.name}"
    YARA_ALERTS_SNS_TOPIC_ARN      = "${aws_sns_topic.yara_match_alerts.arn}"
    SAFE_SNS_TOPIC_ARN             = "${var.enable_safe_alerts == "1" ? "${join("",aws_sns_topic.safe_alerts.*.arn)}" : ""}"
  }

  log_retention_days = "${var.lambda_log_retention_days}"
  tagged_name        = "${var.tagged_name}"

  // During batch operations, the analyzer will have a high error rate because of S3 latency.
  alarm_errors_help = <<EOF
If (a) the number of errors is not growing unbounded,
(b) the errors are correlated with a rise in S3 download latency, and
(c) the batcher is currently running (e.g. after a deploy),
then you can resolve this alert (and consider increasing the threshold for this alarm).
Otherwise, there is an unknown problem with the analyzers (which may still be related to S3).
EOF

  alarm_errors_threshold     = 50
  alarm_errors_interval_secs = 300
  alarm_sns_arns             = ["${aws_sns_topic.metric_alarms.arn}"]
}

// Invoke analyzer Lambda from analyzer SQS queue.
resource "aws_lambda_event_source_mapping" "analyzer_via_sqs" {
  batch_size       = "${var.analyze_queue_batch_size}"
  event_source_arn = "${aws_sqs_queue.analyzer_queue.arn}"
  function_name    = "${module.binaryalert_analyzer.alias_arn}"
}

// Create the batch Lambda function.
module "binaryalert_batcher" {
  source          = "modules/lambda"
  function_name   = "${var.name_prefix}_binaryalert_batcher"
  description     = "Enqueues all S3 objects into SQS for re-analysis"
  base_policy_arn = "${aws_iam_policy.base_policy.arn}"
  handler         = "main.batch_lambda_handler"
  memory_size_mb  = "${var.lambda_batch_memory_mb}"
  timeout_sec     = 300
  filename        = "lambda_batcher.zip"

  environment_variables = {
    BATCH_LAMBDA_NAME      = "${var.name_prefix}_binaryalert_batcher"
    BATCH_LAMBDA_QUALIFIER = "Production"
    OBJECTS_PER_MESSAGE    = "${var.lambda_batch_objects_per_message}"
    S3_BUCKET_NAME         = "${aws_s3_bucket.binaryalert_binaries.id}"
    SQS_QUEUE_URL          = "${aws_sqs_queue.analyzer_queue.id}"
  }

  log_retention_days = "${var.lambda_log_retention_days}"
  tagged_name        = "${var.tagged_name}"
  alarm_sns_arns     = ["${aws_sns_topic.metric_alarms.arn}"]
}

// Create the CarbonBlack downloading Lambda function.
module "binaryalert_downloader" {
  enabled = "${var.enable_carbon_black_downloader}"

  source          = "modules/lambda"
  function_name   = "${var.name_prefix}_binaryalert_downloader"
  description     = "Copies binaries from CarbonBlack into the BinaryAlert S3 bucket"
  base_policy_arn = "${aws_iam_policy.base_policy.arn}"
  handler         = "main.download_lambda_handler"
  memory_size_mb  = "${var.lambda_download_memory_mb}"
  timeout_sec     = "${var.lambda_download_timeout_sec}"
  filename        = "lambda_downloader.zip"

  environment_variables = {
    CARBON_BLACK_URL                 = "${var.carbon_black_url}"
    ENCRYPTED_CARBON_BLACK_API_TOKEN = "${var.encrypted_carbon_black_api_token}"
    TARGET_S3_BUCKET                 = "${aws_s3_bucket.binaryalert_binaries.id}"
  }

  log_retention_days = "${var.lambda_log_retention_days}"
  tagged_name        = "${var.tagged_name}"
  alarm_sns_arns     = ["${aws_sns_topic.metric_alarms.arn}"]
}

// Invoke downloader Lambda from downloader SQS queue.
resource "aws_lambda_event_source_mapping" "downloader_via_sqs" {
  count            = "${var.enable_carbon_black_downloader == 1 ? 1 : 0}"
  batch_size       = "${var.download_queue_batch_size}"
  event_source_arn = "${aws_sqs_queue.downloader_queue.arn}"
  function_name    = "${module.binaryalert_downloader.alias_arn}"
}

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
    SAFE_SNS_TOPIC_ARN             = "${join("", aws_sns_topic.safe_alerts.*.arn)}"
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

// Create the dispatching Lambda function.
module "binaryalert_dispatcher" {
  source          = "modules/lambda"
  function_name   = "${var.name_prefix}_binaryalert_dispatcher"
  description     = "Poll SQS events and fire them off to analyzers"
  base_policy_arn = "${aws_iam_policy.base_policy.arn}"
  handler         = "main.dispatch_lambda_handler"
  memory_size_mb  = "${var.lambda_dispatch_memory_mb}"
  timeout_sec     = "${var.lambda_dispatch_timeout_sec}"
  filename        = "lambda_dispatcher.zip"

  environment_variables = {
    SQS_QUEUE_URLS = "${
        var.enable_carbon_black_downloader == 1 ?
        format("%s,%s", aws_sqs_queue.analyzer_queue.id,
               element(concat(aws_sqs_queue.downloader_queue.*.id, list("")), 0)) :
        aws_sqs_queue.analyzer_queue.id}"

    LAMBDA_TARGETS = "${
        var.enable_carbon_black_downloader == 1 ?
        format("%s:%s,%s:%s", module.binaryalert_analyzer.function_name, module.binaryalert_analyzer.alias_name,
               module.binaryalert_downloader.function_name, module.binaryalert_downloader.alias_name) :
        format("%s:%s", module.binaryalert_analyzer.function_name, module.binaryalert_analyzer.alias_name)}"
  }

  log_retention_days = "${var.lambda_log_retention_days}"
  tagged_name        = "${var.tagged_name}"
  alarm_sns_arns     = ["${aws_sns_topic.metric_alarms.arn}"]
}

// Allow dispatcher to be invoked via a CloudWatch rule.
resource "aws_lambda_permission" "allow_cloudwatch_to_invoke_dispatch" {
  statement_id  = "AllowExecutionFromCloudWatch_${module.binaryalert_dispatcher.function_name}"
  action        = "lambda:InvokeFunction"
  function_name = "${module.binaryalert_dispatcher.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.dispatch_cronjob.arn}"
  qualifier     = "${module.binaryalert_dispatcher.alias_name}"
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

// Create the analyzer Lambda function.
module "binaryalert_analyzer" {
  source          = "./modules/lambda"
  function_name   = "${var.name_prefix}_binaryalert_analyzer"
  description     = "Analyze a binary with a set of YARA rules"
  base_policy_arn = aws_iam_policy.base_policy.arn
  handler         = "lambda_functions.analyzer.main.analyze_lambda_handler"
  memory_size_mb  = var.lambda_analyze_memory_mb
  timeout_sec     = var.lambda_analyze_timeout_sec
  filename        = "lambda_analyzer.zip"

  reserved_concurrent_executions = var.lambda_analyze_concurrency_limit

  environment_variables = {
    NO_MATCHES_SNS_TOPIC_ARN       = element(concat(aws_sns_topic.no_yara_match.*.arn, [""]), 0)
    YARA_MATCHES_DYNAMO_TABLE_NAME = aws_dynamodb_table.binaryalert_yara_matches.name
    YARA_ALERTS_SNS_TOPIC_ARN      = aws_sns_topic.yara_match_alerts.arn
  }

  log_retention_days = var.lambda_log_retention_days
  tagged_name        = var.tagged_name

  // There may be a few errors during a batch analysis when waiting on S3
  alarm_errors_threshold     = 10
  alarm_errors_interval_secs = 300
  alarm_sns_arns             = [local.alarm_target]
}

// Invoke analyzer Lambda from analyzer SQS queue.
resource "aws_lambda_event_source_mapping" "analyzer_via_sqs" {
  batch_size       = var.analyze_queue_batch_size
  event_source_arn = aws_sqs_queue.analyzer_queue.arn
  function_name    = module.binaryalert_analyzer.alias_arn
}

// Create the CarbonBlack downloading Lambda function.
module "binaryalert_downloader" {
  enabled         = var.enable_carbon_black_downloader ? 1 : 0
  source          = "./modules/lambda"
  function_name   = "${var.name_prefix}_binaryalert_downloader"
  description     = "Copies binaries from CarbonBlack into the BinaryAlert S3 bucket"
  base_policy_arn = aws_iam_policy.base_policy.arn
  handler         = "lambda_functions.downloader.main.download_lambda_handler"
  memory_size_mb  = var.lambda_download_memory_mb
  timeout_sec     = var.lambda_download_timeout_sec
  filename        = "lambda_downloader.zip"

  reserved_concurrent_executions = var.lambda_download_concurrency_limit

  environment_variables = {
    CARBON_BLACK_URL                 = var.carbon_black_url
    CARBON_BLACK_TIMEOUT             = var.carbon_black_timeout
    ENCRYPTED_CARBON_BLACK_API_TOKEN = var.encrypted_carbon_black_api_token
    TARGET_S3_BUCKET                 = aws_s3_bucket.binaryalert_binaries.id
  }

  log_retention_days = var.lambda_log_retention_days
  tagged_name        = var.tagged_name

  alarm_errors_threshold = 500
  alarm_sns_arns         = [local.alarm_target]
}

// Invoke downloader Lambda from downloader SQS queue.
resource "aws_lambda_event_source_mapping" "downloader_via_sqs" {
  count            = var.enable_carbon_black_downloader ? 1 : 0
  batch_size       = var.download_queue_batch_size
  event_source_arn = aws_sqs_queue.downloader_queue[0].arn
  function_name    = module.binaryalert_downloader.alias_arn
}


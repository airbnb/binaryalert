/* CloudWatch alarms fire if metrics look abnormal. */

locals {
  // Use the existing SNS alarm topic if specified, otherwise use the created one
  alarm_target = element(
    concat(
      aws_sns_topic.metric_alarms.*.arn,
      [var.metric_alarm_sns_topic_arn],
    ),
    0,
  )
}

// The production BinaryAlert analyzer is not analyzing binaries.
resource "aws_cloudwatch_metric_alarm" "analyzed_binaries" {
  alarm_name = "${module.binaryalert_analyzer.function_name}_no_analyzed_binaries"

  alarm_description = <<EOF
${module.binaryalert_analyzer.function_name} is not analyzing any binaries!
  - If any BinaryAlert Lambda function was recently deployed, roll it back via the AWS console.
  - Binaries may not be arriving in the S3 bucket.
EOF


  namespace   = "BinaryAlert"
  metric_name = "AnalyzedBinaries"
  statistic   = "Sum"

  // No binaries analyzed for a while.
  comparison_operator = "LessThanOrEqualToThreshold"
  threshold           = 0
  period              = format("%d", var.expected_analysis_frequency_minutes * 60)
  evaluation_periods  = 1

  alarm_actions             = [local.alarm_target]
  insufficient_data_actions = [local.alarm_target]
}

// The analyzer SQS queue is falling behind.
resource "aws_cloudwatch_metric_alarm" "analyzer_sqs_age" {
  alarm_name = "${aws_sqs_queue.analyzer_queue.name}_old_age"

  alarm_description = <<EOF
The queue ${aws_sqs_queue.analyzer_queue.name} is not being processed quickly enough:
messages are reaching 75% of the queue retention and may be expired soon.
  - Consider increasing the lambda_analyze_concurrency_limit to process more events
  - Consider raising the retention period for this queue
EOF


  namespace   = "AWS/SQS"
  metric_name = "ApproximateAgeOfOldestMessage"
  statistic   = "Minimum"

  dimensions = {
    QueueName = aws_sqs_queue.analyzer_queue.name
  }

  comparison_operator = "GreaterThanThreshold"
  threshold           = format("%d", ceil(var.analyze_queue_retention_secs * 0.75))
  period              = 60
  evaluation_periods  = 10

  alarm_actions             = [local.alarm_target]
  insufficient_data_actions = [local.alarm_target]
}

// The downloader SQS queue is falling behind.
resource "aws_cloudwatch_metric_alarm" "downloader_sqs_age" {
  count      = var.enable_carbon_black_downloader ? 1 : 0
  alarm_name = "${aws_sqs_queue.downloader_queue[0].name}_old_age"

  alarm_description = <<EOF
The queue ${aws_sqs_queue.downloader_queue[0].name} is not being processed quickly enough:
messages are reaching 75% of the queue retention and may be expired soon.
  - Consider increasing the lambda_download_concurrency_limit to process more events
  - Consider raising the retention period for this queue
EOF


  namespace   = "AWS/SQS"
  metric_name = "ApproximateAgeOfOldestMessage"
  statistic   = "Minimum"

  dimensions = {
    QueueName = aws_sqs_queue.downloader_queue[0].name
  }

  comparison_operator = "GreaterThanThreshold"
  threshold           = format("%d", ceil(var.download_queue_retention_secs * 0.75))
  period              = 60
  evaluation_periods  = 10

  alarm_actions             = [local.alarm_target]
  insufficient_data_actions = [local.alarm_target]
}

// There are very few YARA rules.
resource "aws_cloudwatch_metric_alarm" "yara_rules" {
  alarm_name = "${module.binaryalert_analyzer.function_name}_too_few_yara_rules"

  alarm_description = <<EOF
The number of YARA rules in BinaryAlert is surprisingly low.
Check if a recent deploy accidentally removed most YARA rules.
EOF


  namespace   = "BinaryAlert"
  metric_name = "YaraRules"
  statistic   = "Maximum"

  // Less than 5 YARA rules for at least 5 minutes.
  comparison_operator = "LessThanThreshold"
  threshold           = 5
  period              = 300
  evaluation_periods  = 1

  alarm_actions = [local.alarm_target]
}

// Dynamo requests are being throttled.
resource "aws_cloudwatch_metric_alarm" "dynamo_throttles" {
  alarm_name = "${aws_dynamodb_table.binaryalert_yara_matches.name}_throttles"

  alarm_description = <<EOF
Read or write requests to the BinaryAlert DynamoDB table are being throttled.
  - Check the ReadThrottleEvents and WriteThrottleEvents Dynamo metrics to understand which
    operation is causing throttles.
  - If there was a recent deploy with new YARA rules, there may be more matches than Dynamo has been
    provisioned to handle. In this case, rollback the analyzer in the AWS Console and fix the rules.
  - If this is normal/expected behavior, increase the dynamo_read_capacity in the BinaryAlet config.
EOF


  namespace   = "AWS/DynamoDB"
  metric_name = "ThrottledRequests"
  statistic   = "Sum"

  dimensions = {
    TableName = aws_dynamodb_table.binaryalert_yara_matches.name
  }

  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  period              = 60
  evaluation_periods  = 1

  alarm_actions = [local.alarm_target]
}


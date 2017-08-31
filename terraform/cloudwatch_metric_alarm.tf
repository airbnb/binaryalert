/* CloudWatch alarms fire if metrics look abnormal. */

// The batch function had an error enqueueing an S3 key.
resource "aws_cloudwatch_metric_alarm" "batch_enqueue_errors" {
  alarm_name = "${module.binaryalert_batcher.function_name}_enqueue_errors"

  alarm_description = <<EOF
${module.binaryalert_batcher.function_name} failed to enqueue one or more S3 keys into the SQS queue
${aws_sqs_queue.s3_object_queue.arn}.
  - Check the batcher CloudWatch logs.
  - SQS may be down.
  - Once the problem has been resolved, re-execute the batcher (`manage.py analyze_all`) to analyze
any files which might have been missed.
EOF

  namespace   = "BinaryAlert"
  metric_name = "BatchEnqueueFailures"
  statistic   = "Sum"

  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  period              = 60
  evaluation_periods  = 1
  alarm_actions       = ["${aws_sns_topic.metric_alarms.arn}"]
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
  comparison_operator       = "LessThanOrEqualToThreshold"
  threshold                 = 0
  period                    = "${format("%d", var.expected_analysis_frequency_minutes * 60)}"
  evaluation_periods        = 1
  alarm_actions             = ["${aws_sns_topic.metric_alarms.arn}"]
  insufficient_data_actions = ["${aws_sns_topic.metric_alarms.arn}"]
}

// The SQS queue is falling behind.
resource "aws_cloudwatch_metric_alarm" "sqs_age" {
  alarm_name = "${aws_sqs_queue.s3_object_queue.name}_old_age"

  alarm_description = <<EOF
The queue ${aws_sqs_queue.s3_object_queue.name} is falling behind and items are growing old.
This can sometimes happen during a batch analysis of the entire bucket (e.g. after a deploy).
  - If the SQS age is growing unbounded ("up and to the right"), either the analyzers are down or
    they are unable to pull from SQS. Check the analyzer logs.
  - If the batcher is currently running and the SQS age is relatively stable, resolve the alert and
    consider increasing the threshold for this alert.
EOF

  namespace   = "AWS/SQS"
  metric_name = "ApproximateAgeOfOldestMessage"
  statistic   = "Minimum"

  dimensions = {
    QueueName = "${aws_sqs_queue.s3_object_queue.name}"
  }

  // The queue is consistently more than 30 minutes behind.
  comparison_operator       = "GreaterThanThreshold"
  threshold                 = 1800
  period                    = 60
  evaluation_periods        = 15
  alarm_actions             = ["${aws_sns_topic.metric_alarms.arn}"]
  insufficient_data_actions = ["${aws_sns_topic.metric_alarms.arn}"]
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
  alarm_actions       = ["${aws_sns_topic.metric_alarms.arn}"]
}

// Dynamo requests are being throttled.
resource "aws_cloudwatch_metric_alarm" "dynamo_throttles" {
  alarm_name = "${aws_dynamodb_table.binaryalert_yara_matches.name}_throttles"

  alarm_description = <<EOF
Read or write requests to the DynamoDB table are being throttled.
  - Check the ReadThrottleEvents and WriteThrottleEvents Dynamo metrics to understand which
    operation is causing throttles.
  - If there was a recent deploy with new YARA rules, there may be more matches than Dynamo has been
    provisioned to handle. In this case, rollback the analyzer in the AWS Console and fix the rules.
  - If this is normal/expected behavior, increase the read capacity for the Dynamo table in the
    BinaryAlert terraform.tfvars config file.
EOF

  namespace   = "AWS/DynamoDB"
  metric_name = "ThrottledRequests"
  statistic   = "Sum"

  dimensions = {
    TableName = "${aws_dynamodb_table.binaryalert_yara_matches.name}"
  }

  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  period              = 60
  evaluation_periods  = 1
  alarm_actions       = ["${aws_sns_topic.metric_alarms.arn}"]
}

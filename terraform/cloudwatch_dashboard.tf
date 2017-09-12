// CloudWatch dashboard for BinaryAlert

locals {
  /* Ideally, each widget could be described with Terraform objects instead of raw JSON, but
     Terraform does not yet support complex types (in particular, lists of maps are not allowed). */

  s3_bucket_stats = <<EOF
{
  "type": "metric",
  "width": 12,
  "height": 3,
  "properties": {
    "title": "S3: ${aws_s3_bucket.binaryalert_binaries.id}",
    "region": "${var.aws_region}",
    "stat": "Average",
    "period": 86400,
    "view": "singleValue",
    "metrics": [
      ["AWS/S3", "NumberOfObjects", "BucketName", "${aws_s3_bucket.binaryalert_binaries.id}"],
      [".", "BucketSizeBytes", ".", "."]
    ]
  }
}
EOF

  yara_rules = <<EOF
{
  "type": "metric",
  "width": 12,
  "height": 3,
  "properties": {
    "title": "YARA Rules",
    "region": "${var.aws_region}",
    "stat": "Average",
    "period": 60,
    "view": "singleValue",
    "metrics": [
      ["BinaryAlert", "YaraRules", {"label": "YARA Rules"}]
    ]
  }
}
EOF

  analyzed_binaries = <<EOF
{
  "type": "metric",
  "width": 12,
  "properties": {
    "title": "Analyzed Binaries",
    "region": "${var.aws_region}",
    "stat": "Sum",
    "metrics": [
      ["BinaryAlert", "AnalyzedBinaries"],
      [".", "MatchedBinaries"]
    ]
  }
}
EOF

  sqs = <<EOF
{
  "type": "metric",
  "width": 12,
  "properties": {
    "title": "SQS: ${aws_sqs_queue.s3_object_queue.name}",
    "region": "${var.aws_region}",
    "stat": "Sum",
    "metrics": [
      ["AWS/SQS", "NumberOfMessagesSent", "QueueName", "${aws_sqs_queue.s3_object_queue.name}"],
      [".", "NumberOfMessagesReceived", ".", "."],
      [".", "ApproximateNumberOfMessagesVisible", ".", ".", {"stat": "Average"}]
    ]
  }
}
EOF

  sqs_age = <<EOF
{
  "type": "metric",
  "width": 12,
  "properties": {
    "title": "SQS Age Of Oldest Message (Seconds)",
    "region": "${var.aws_region}",
    "stat": "Average",
    "metrics": [
      [
        "AWS/SQS", "ApproximateAgeOfOldestMessage",
        "QueueName", "${aws_sqs_queue.s3_object_queue.name}"
      ]
    ],
    "annotations": {
      "horizontal": [
        {
          "label": "Maximum Age",
          "value": ${aws_sqs_queue.s3_object_queue.message_retention_seconds}
        },
        {
          "label": "High Age Alarm",
          "value": ${aws_cloudwatch_metric_alarm.sqs_age.threshold}
        }
      ]
    }
  }
}
EOF

  // Due to https://github.com/hashicorp/terraform/issues/11574, both ternary branches are always
  // computed. This means we have to build the downloader name explicitly instead of referencing
  // the (possibly non-existent) downloader module.
  downloader_function_name = "${var.name_prefix}_binaryalert_downloader"

  downloader = <<EOF
    ,[".", ".", ".", "${local.downloader_function_name}", {"label": "Downloader"}]
EOF

  // Build common lists for batcher, dispatcher, downloader.
  other_functions = <<EOF
    [".", ".", ".", "${module.binaryalert_batcher.function_name}", {"label": "Batcher"}],
    [".", ".", ".", "${module.binaryalert_dispatcher.function_name}", {"label": "Dispatcher"}]
    ${var.enable_carbon_black_downloader == 1 ? local.downloader : ""}
EOF

  lambda_invocations = <<EOF
{
  "type": "metric",
  "width": 12,
  "properties": {
    "title": "Lambda Invocations",
    "region": "${var.aws_region}",
    "stat": "Sum",
    "metrics": [
      [
        "AWS/Lambda", "Invocations",
        "FunctionName", "${module.binaryalert_analyzer.function_name}",
        {"label": "Analyzer"}
      ],
      ${local.other_functions}
    ]
  }
}
EOF

  max_lambda_duration = <<EOF
{
  "type": "metric",
  "width": 12,
  "properties": {
    "title": "Maximum Lambda Duration (ms)",
    "region": "${var.aws_region}",
    "stat": "Maximum",
    "metrics": [
      [
        "AWS/Lambda", "Duration",
        "FunctionName", "${module.binaryalert_analyzer.function_name}",
        {"label": "Analyzer"}
      ],
      ${local.other_functions}
    ],
    "annotations": {
      "horizontal": [
        {
          "label": "Maximum",
          "value": 300000
        }
      ]
    }
  }
}
EOF

  lambda_errors = <<EOF
{
  "type": "metric",
  "width": 12,
  "properties": {
    "title": "Lambda Errors",
    "region": "${var.aws_region}",
    "stat": "Sum",
    "metrics": [
      [
        "AWS/Lambda", "Errors",
        "FunctionName", "${module.binaryalert_analyzer.function_name}",
        {"label": "Analyzer"}
      ],
      ${local.other_functions}
    ]
  }
}
EOF

  lambda_throttles = <<EOF
{
  "type": "metric",
  "width": 12,
  "properties": {
    "title": "Lambda Throttles",
    "region": "${var.aws_region}",
    "stat": "Sum",
    "metrics": [
      [
        "AWS/Lambda", "Throttles",
        "FunctionName", "${module.binaryalert_analyzer.function_name}",
        {"label": "Analyzer"}
      ],
      ${local.other_functions}
    ]
  }
}
EOF

  s3_download_latency = <<EOF
{
  "type": "metric",
  "width": 12,
  "properties": {
    "title": "S3 Download Latency (ms)",
    "region": "${var.aws_region}",
    "metrics": [
      ["BinaryAlert", "S3DownloadLatency", {"label": "Minimum", "stat": "Minimum"}],
      [".", ".", {"label": "Average", "stat": "Average"}],
      [".", ".", {"label": "Maximum", "stat": "Maximum"}]
    ]
  }
}
EOF

  sns_publications = <<EOF
{
  "type": "metric",
  "width": 12,
  "properties": {
    "title": "SNS Publications",
    "region": "${var.aws_region}",
    "stat": "Sum",
    "metrics": [
      [
        "AWS/SNS", "NumberOfMessagesPublished",
        "TopicName", "${aws_sns_topic.yara_match_alerts.name}",
        {"label": "YARA Match Alerts"}
      ],
      [".", ".", ".", "${aws_sns_topic.metric_alarms.name}", {"label": "Metric Alarms"}]
    ]
  }
}
EOF

  downloader_logs = <<EOF
    ,[".", ".", ".", "/aws/lambda/${local.downloader_function_name}", {"label": "Downloader"}]
EOF

  log_bytes = <<EOF
{
  "type": "metric",
  "width": 12,
  "properties": {
    "title": "BinaryAlert Logs (Bytes)",
    "region": "${var.aws_region}",
    "stacked": true,
    "stat": "Sum",
    "metrics": [
      [
        "AWS/Logs", "IncomingBytes",
        "LogGroupName", "${module.binaryalert_analyzer.log_group_name}",
        {"label": "Analyzer"}
      ],
      [".", ".", ".", "${module.binaryalert_batcher.log_group_name}", {"label": "Batcher"}],
      [".", ".", ".", "${module.binaryalert_dispatcher.log_group_name}", {"label": "Dispatcher"}]
      ${var.enable_carbon_black_downloader == 1 ? local.downloader_logs : ""}
    ]
  }
}
EOF

  dashboard_body = <<EOF
{
  "widgets": [
    ${local.s3_bucket_stats}, ${local.yara_rules},
    ${local.analyzed_binaries}, ${local.sns_publications},
    ${local.sqs}, ${local.sqs_age},
    ${local.lambda_invocations}, ${local.max_lambda_duration},
    ${local.lambda_errors}, ${local.lambda_throttles},
    ${local.s3_download_latency}, ${local.log_bytes}
  ]
}
EOF
}

resource "aws_cloudwatch_dashboard" "binaryalert" {
  dashboard_name = "BinaryAlert"
  dashboard_body = "${local.dashboard_body}"
}

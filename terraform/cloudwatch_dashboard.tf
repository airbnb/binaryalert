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
      [
        "AWS/S3", "NumberOfObjects",
        "BucketName", "${aws_s3_bucket.binaryalert_binaries.id}",
        "StorageType", "AllStorageTypes"
      ],
      [".", "BucketSizeBytes", ".", ".", ".", "StandardStorage"]
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


  sqs_analyzer = <<EOF
{
  "type": "metric",
  "width": 12,
  "properties": {
    "title": "SQS: ${aws_sqs_queue.analyzer_queue.name}",
    "region": "${var.aws_region}",
    "stat": "Sum",
    "metrics": [
      ["AWS/SQS", "NumberOfMessagesSent", "QueueName", "${aws_sqs_queue.analyzer_queue.name}"],
      [".", "NumberOfMessagesReceived", ".", "."],
      [".", "ApproximateNumberOfMessagesVisible", ".", ".", {"stat": "Average"}]
    ]
  }
}
EOF


  sqs_analyzer_age = <<EOF
{
  "type": "metric",
  "width": 12,
  "properties": {
    "title": "Analyzer SQS - Age Of Oldest Message",
    "region": "${var.aws_region}",
    "stat": "Average",
    "metrics": [
      [
        "AWS/SQS", "ApproximateAgeOfOldestMessage",
        "QueueName", "${aws_sqs_queue.analyzer_queue.name}"
      ]
    ],
    "annotations": {
      "horizontal": [
        {
          "label": "Max",
          "value": ${aws_sqs_queue.analyzer_queue.message_retention_seconds}
        },
        {
          "label": "Alarm",
          "value": ${aws_cloudwatch_metric_alarm.analyzer_sqs_age.threshold}
        }
      ]
    }
  }
}
EOF


  // Due to https://github.com/hashicorp/terraform/issues/11574, both ternary branches are always
  // computed, so we have to use this special idiom (same as modules/lambda/outputs.tf).
  downloader_function_name = module.binaryalert_downloader.function_name

  downloader_queue_name = element(concat(aws_sqs_queue.downloader_queue.*.name, [""]), 0)

  sqs_downloader = <<EOF
{
  "type": "metric",
  "width": 12,
  "properties": {
    "title": "SQS: ${local.downloader_queue_name}",
    "region": "${var.aws_region}",
    "stat": "Sum",
    "metrics": [
      ["AWS/SQS", "NumberOfMessagesSent", "QueueName", "${local.downloader_queue_name}"],
      [".", "NumberOfMessagesReceived", ".", "."],
      [".", "ApproximateNumberOfMessagesVisible", ".", ".", {"stat": "Average"}]
    ]
  }
}
EOF


  sqs_downloader_age = <<EOF
{
  "type": "metric",
  "width": 12,
  "properties": {
    "title": "Downloader SQS - Age Of Oldest Message",
    "region": "${var.aws_region}",
    "stat": "Average",
    "metrics": [
      [
        "AWS/SQS", "ApproximateAgeOfOldestMessage",
        "QueueName", "${local.downloader_queue_name}"
      ]
    ],
    "annotations": {
      "horizontal": [
        {
          "label": "Max",
          "value": "${element(
  concat(
    aws_sqs_queue.downloader_queue.*.message_retention_seconds,
    [""],
  ),
  0,
  )}"
        },
        {
          "label": "Alarm",
          "value": "${element(
  concat(
    aws_cloudwatch_metric_alarm.downloader_sqs_age.*.threshold,
    [""],
  ),
  0,
)}"
        }
      ]
    }
  }
}
EOF


downloader = <<EOF
    ,[".", ".", ".", "${local.downloader_function_name}", {"label": "Downloader"}]
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
      ]
      ${var.enable_carbon_black_downloader ? local.downloader : ""}
    ]
  }
}
EOF


max_lambda_duration = <<EOF
{
  "type": "metric",
  "width": 12,
  "properties": {
    "title": "Maximum Lambda Duration",
    "region": "${var.aws_region}",
    "stat": "Maximum",
    "metrics": [
      [
        "AWS/Lambda", "Duration",
        "FunctionName", "${module.binaryalert_analyzer.function_name}",
        {"label": "Analyzer"}
      ]
      ${var.enable_carbon_black_downloader ? local.downloader : ""}
    ],
    "annotations": {
      "horizontal": [
        {
          "label": "Max",
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
      ]
      ${var.enable_carbon_black_downloader ? local.downloader : ""}
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
      ]
      ${var.enable_carbon_black_downloader ? local.downloader : ""}
    ]
  }
}
EOF


s3_download_latency = <<EOF
{
  "type": "metric",
  "width": 12,
  "properties": {
    "title": "S3 Download Latency",
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
      [".", ".", ".", "${element(split(":", local.alarm_target), 5)}", {"label": "Metric Alarms"}]
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
    "title": "BinaryAlert Logs",
    "region": "${var.aws_region}",
    "stacked": true,
    "stat": "Sum",
    "metrics": [
      [
        "AWS/Logs", "IncomingBytes",
        "LogGroupName", "${module.binaryalert_analyzer.log_group_name}",
        {"label": "Analyzer"}
      ]
      ${var.enable_carbon_black_downloader ? local.downloader_logs : ""}
    ]
  }
}
EOF


dashboard_body_without_downloader = <<EOF
{
  "widgets": [
    ${local.s3_bucket_stats}, ${local.yara_rules},
    ${local.analyzed_binaries}, ${local.sns_publications},
    ${local.sqs_analyzer}, ${local.sqs_analyzer_age},
    ${local.lambda_invocations}, ${local.max_lambda_duration},
    ${local.lambda_errors}, ${local.lambda_throttles},
    ${local.s3_download_latency}, ${local.log_bytes}
  ]
}
EOF


dashboard_body_with_downloader = <<EOF
{
  "widgets": [
    ${local.s3_bucket_stats}, ${local.yara_rules},
    ${local.analyzed_binaries}, ${local.sns_publications},
    ${local.sqs_analyzer}, ${local.sqs_analyzer_age},
    ${local.sqs_downloader}, ${local.sqs_downloader_age},
    ${local.lambda_invocations}, ${local.max_lambda_duration},
    ${local.lambda_errors}, ${local.lambda_throttles},
    ${local.s3_download_latency}, ${local.log_bytes}
  ]
}
EOF


dashboard_body = var.enable_carbon_black_downloader ? local.dashboard_body_with_downloader : local.dashboard_body_without_downloader
}

resource "aws_cloudwatch_dashboard" "binaryalert" {
  dashboard_name = "BinaryAlert"

  // Terraform automatically converts numbers to strings when putting them in a list.
  // We have to strip quotes around numbers, so that {"value": "123"} turns into {"value": 123}
  dashboard_body = replace(local.dashboard_body, "/\"([0-9]+)\"/", "$1")
}


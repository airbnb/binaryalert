// CloudWatch dashboard for BinaryAlert

locals {
  // Ideally, each widget could be described with Terraform objects instead of raw JSON, but
  // Terraform does not yet support complex types (in particular, lists of maps are not allowed).

  analyzed_binaries = <<EOF
{
  "type": "metric",
  "width": 12,
  "properties": {
    "title": "Analyzed Binaries",
    "region": "${var.aws_region}",
    "stat": "Sum",
    "period": 300,
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
    "period": 300,
    "metrics": [
      ["AWS/SQS", "NumberOfMessagesSent", "QueueName", "${aws_sqs_queue.s3_object_queue.name}"],
      [".", "NumberOfMessagesReceived", ".", "."],
      [".", "ApproximateNumberOfMessagesVisible", ".", ".", {"stat": "Average"}],
      [".", "ApproximateAgeOfOldestMessage", ".", ".", {"stat": "Average", "yAxis": "right"}]
    ]
  }
}
EOF

  lambda_invocations = <<EOF
{
  "type": "metric",
  "width": 12,
  "properties": {
    "title": "Lambda Invocations",
    "region": "${var.aws_region}",
    "stat": "Sum",
    "period": 300,
    "metrics": [
      [
        "AWS/Lambda", "Invocations",
        "FunctionName", "${module.binaryalert_analyzer.function_name}",
        {"label": "Analyzer"}
      ],
      [".", ".", ".", "${module.binaryalert_batcher.function_name}", {"label": "Batcher"}],
      [".", ".", ".", "${module.binaryalert_dispatcher.function_name}", {"label": "Dispatcher"}]
    ]
  }
}
EOF

  dashboard_body = <<EOF
{
  "widgets": [
    ${local.analyzed_binaries}, ${local.sqs},
    ${local.lambda_invocations}
  ]
}
EOF
}

resource "aws_cloudwatch_dashboard" "binaryalert" {
  dashboard_name = "BinaryAlert"

  // Encode to JSON and remove quotes around numbers.
  dashboard_body = "${local.dashboard_body}"
}

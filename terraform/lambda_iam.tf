/* Define IAM permissions for the Lambda functions. */

data "aws_iam_policy_document" "base_policy" {
  statement {
    sid = "EnableLogsAndMetrics"

    actions = [
      "cloudwatch:PutMetricData",
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["*"]
  }
}

resource "aws_iam_policy" "base_policy" {
  name   = "${var.name_prefix}_binaryalert_base_policy"
  policy = data.aws_iam_policy_document.base_policy.json
}

// ********** Analyzer **********

data "aws_iam_policy_document" "binaryalert_analyzer_policy" {
  statement {
    sid = "QueryAndUpdateDynamo"

    actions = [
      "dynamodb:PutItem",
      "dynamodb:Query",
      "dynamodb:UpdateItem",
    ]

    resources = [aws_dynamodb_table.binaryalert_yara_matches.arn]
  }

  statement {
    sid = "DecryptSSE"

    actions = [
      "kms:Decrypt",
      "kms:Describe*",
    ]

    resources = concat(
      [aws_kms_key.sse_s3.arn, aws_kms_key.sse_sqs.arn],
      var.external_kms_key_resources,
    )
  }

  statement {
    sid = "GetFromS3Bucket"

    actions = [
      "s3:GetObject*",
      "s3:HeadObject",
    ]

    resources = concat(
      [format("%s/*", aws_s3_bucket.binaryalert_binaries.arn)],
      var.external_s3_bucket_resources,
    )
  }

  statement {
    sid     = "PublishAlertsToSNS"
    actions = ["sns:Publish"]

    resources = concat(
      [aws_sns_topic.yara_match_alerts.arn],
      aws_sns_topic.no_yara_match.*.arn,
    )
  }

  statement {
    sid = "ProcessSQSMessages"

    actions = [
      "sqs:ChangeMessageVisibility",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:ReceiveMessage",
    ]

    resources = [aws_sqs_queue.analyzer_queue.arn]
  }
}

resource "aws_iam_role_policy" "binaryalert_analyzer_policy" {
  name   = "${var.name_prefix}_binaryalert_analyzer_policy"
  role   = module.binaryalert_analyzer.role_id
  policy = data.aws_iam_policy_document.binaryalert_analyzer_policy.json
}

// ********** Downloader **********

data "aws_iam_policy_document" "binaryalert_downloader_policy" {
  count = var.enable_carbon_black_downloader ? 1 : 0

  statement {
    sid = "AllowSSE"

    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
    ]

    resources = [
      aws_kms_key.sse_s3.arn,
      aws_kms_key.sse_sqs.arn,
    ]
  }

  statement {
    sid       = "DecryptCarbonBlackCredentials"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.carbon_black_credentials[0].arn]
  }

  statement {
    sid       = "UploadToBinaryAlertBucket"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.binaryalert_binaries.arn}/*"]
  }

  statement {
    sid = "ProcessSQSMessages"

    actions = [
      "sqs:ChangeMessageVisibility",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:ReceiveMessage",
    ]

    resources = [aws_sqs_queue.downloader_queue[0].arn]
  }
}

resource "aws_iam_role_policy" "binaryalert_downloader_policy" {
  count  = var.enable_carbon_black_downloader ? 1 : 0
  name   = "${var.name_prefix}_binaryalert_downloader_policy"
  role   = module.binaryalert_downloader.role_id
  policy = data.aws_iam_policy_document.binaryalert_downloader_policy[0].json
}


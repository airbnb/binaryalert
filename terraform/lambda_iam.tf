/* Define IAM permissions for the Lambda functions. */

data "aws_iam_policy_document" "base_policy" {
  statement {
    sid    = "EnableLogsAndMetrics"
    effect = "Allow"

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
  policy = "${data.aws_iam_policy_document.base_policy.json}"
}

data "aws_iam_policy_document" "binaryalert_downloader_policy" {
  count = "${var.enable_carbon_black_downloader}"

  statement {
    sid       = "DecryptCarbonBlackCredentials"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = ["${aws_kms_key.carbon_black_credentials.arn}"]
  }

  statement {
    sid       = "UploadToBinaryAlertBucket"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.binaryalert_binaries.arn}/*"]
  }
}

resource "aws_iam_role_policy" "binaryalert_downloader_policy" {
  count  = "${var.enable_carbon_black_downloader}"
  name   = "${var.name_prefix}_binaryalert_downloader_policy"
  role   = "${module.binaryalert_downloader.role_id}"
  policy = "${data.aws_iam_policy_document.binaryalert_downloader_policy.json}"
}

data "aws_iam_policy_document" "binaryalert_batcher_policy" {
  statement {
    sid       = "InvokeBinaryAlertBatcher"
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = ["${module.binaryalert_batcher.function_arn}"]
  }

  statement {
    sid       = "ListBinaryAlertBucket"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = ["${aws_s3_bucket.binaryalert_binaries.arn}"]
  }

  statement {
    sid       = "SendMessageToSQS"
    effect    = "Allow"
    actions   = ["sqs:SendMessage*"]
    resources = ["${aws_sqs_queue.s3_object_queue.arn}"]
  }
}

resource "aws_iam_role_policy" "binaryalert_batcher_policy" {
  name   = "${var.name_prefix}_binaryalert_batcher_policy"
  role   = "${module.binaryalert_batcher.role_id}"
  policy = "${data.aws_iam_policy_document.binaryalert_batcher_policy.json}"
}

data "aws_iam_policy_document" "binaryalert_dispatcher_policy" {
  statement {
    sid       = "InvokeBinaryAlertAnalyzer"
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = ["${module.binaryalert_analyzer.function_arn}"]
  }

  statement {
    sid    = "ProcessSQSMessages"
    effect = "Allow"

    actions = [
      "sqs:DeleteMessage",
      "sqs:ReceiveMessage",
    ]

    resources = ["${aws_sqs_queue.s3_object_queue.arn}"]
  }
}

resource "aws_iam_role_policy" "binaryalert_dispatcher_policy" {
  name   = "${var.name_prefix}_binaryalert_dispatcher_policy"
  role   = "${module.binaryalert_dispatcher.role_id}"
  policy = "${data.aws_iam_policy_document.binaryalert_dispatcher_policy.json}"
}

data "aws_iam_policy_document" "binaryalert_analyzer_policy" {
  statement {
    sid    = "QueryAndUpdateDynamo"
    effect = "Allow"

    actions = [
      "dynamodb:PutItem",
      "dynamodb:Query",
      "dynamodb:UpdateItem",
    ]

    resources = ["${aws_dynamodb_table.binaryalert_yara_matches.arn}"]
  }

  statement {
    sid       = "GetFromBinaryAlertBucket"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.binaryalert_binaries.arn}/*"]
  }

  statement {
    sid       = "PublishAlertsToSNS"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = ["${aws_sns_topic.yara_match_alerts.arn}"]
  }

  statement {
    sid       = "DeleteSQSMessages"
    effect    = "Allow"
    actions   = ["sqs:DeleteMessage"]
    resources = ["${aws_sqs_queue.s3_object_queue.arn}"]
  }
}

resource "aws_iam_role_policy" "binaryalert_analyzer_policy" {
  name   = "${var.name_prefix}_binaryalert_analyzer_policy"
  role   = "${module.binaryalert_analyzer.role_id}"
  policy = "${data.aws_iam_policy_document.binaryalert_analyzer_policy.json}"
}

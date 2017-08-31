/* Module to create the base components for each Lambda function. */

data "aws_iam_policy_document" "lambda_execution_policy" {
  count = "${var.enabled}"

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

// Create a custom execution role for each Lambda function.
resource "aws_iam_role" "role" {
  count              = "${var.enabled}"
  name               = "${var.function_name}_role"
  assume_role_policy = "${data.aws_iam_policy_document.lambda_execution_policy.json}"
}

// Attach the base IAM policy.
resource "aws_iam_role_policy_attachment" "attach_base_policy" {
  count      = "${var.enabled}"
  role       = "${aws_iam_role.role.name}"
  policy_arn = "${var.base_policy_arn}"
}

// Create the Lambda log group.
resource "aws_cloudwatch_log_group" "lambda_log_group" {
  count             = "${var.enabled}"
  name              = "/aws/lambda/${var.function_name}"
  retention_in_days = "${var.log_retention_days}"

  tags {
    Name = "BinaryAlert"
  }
}

// Create the Lambda function.
resource "aws_lambda_function" "function" {
  count = "${var.enabled}"

  function_name = "${var.function_name}"
  description   = "${var.description}"
  handler       = "${var.handler}"
  role          = "${aws_iam_role.role.arn}"
  runtime       = "python3.6"

  memory_size = "${var.memory_size_mb}"
  timeout     = "${var.timeout_sec}"

  filename         = "${var.filename}"
  source_code_hash = "${base64sha256(file(var.filename))}"
  publish          = true

  environment {
    variables = "${var.environment_variables}"
  }

  tags {
    Name = "BinaryAlert"
  }
}

// Create a Production alias for each Lambda function.
resource "aws_lambda_alias" "production_alias" {
  count            = "${var.enabled}"
  name             = "Production"
  function_name    = "${aws_lambda_function.function.arn}"
  function_version = "${aws_lambda_function.function.version}"
}

// Alarm if the Lambda function has more than the configured number of errors.
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  count      = "${var.enabled}"
  alarm_name = "${var.function_name}_errors"

  alarm_description = <<EOF
${var.function_name} has a high error rate. Check the CloudWatch logs.
${var.alarm_errors_help}
EOF

  namespace   = "AWS/Lambda"
  metric_name = "Errors"
  statistic   = "Sum"

  dimensions = {
    FunctionName = "${aws_lambda_function.function.function_name}"
    Resource     = "${aws_lambda_function.function.function_name}:${aws_lambda_alias.production_alias.name}"
  }

  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = "${var.alarm_errors_threshold}"
  period              = "${var.alarm_errors_interval_secs}"
  evaluation_periods  = 1

  alarm_actions = ["${var.alarm_sns_arns}"]
}

// Alarm if the Lambda function is ever throttled.
resource "aws_cloudwatch_metric_alarm" "lambda_throttles" {
  count      = "${var.enabled}"
  alarm_name = "${var.function_name}_throttles"

  alarm_description = <<EOF
${var.function_name} is being throttled,
i.e. the number of concurrent Lambda invocations is exceeding your account limit in this region.
Lower the lamda_dispatch_limit in the BinaryAlert config or request an AWS limit increase.
EOF

  namespace   = "AWS/Lambda"
  metric_name = "Throttles"
  statistic   = "Sum"

  dimensions = {
    FunctionName = "${aws_lambda_function.function.function_name}"
    Resource     = "${aws_lambda_function.function.function_name}:${aws_lambda_alias.production_alias.name}"
  }

  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  period              = 60
  evaluation_periods  = 1

  alarm_actions = ["${var.alarm_sns_arns}"]
}

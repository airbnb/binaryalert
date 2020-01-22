/* Module to create the base components for each Lambda function. */

data "aws_iam_policy_document" "lambda_execution_policy" {
  count = var.enabled

  statement {
    sid     = "AllowLambdaToAssumeRole"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

// Create a custom execution role for each Lambda function.
resource "aws_iam_role" "role" {
  count              = var.enabled
  name               = "${var.function_name}_role"
  assume_role_policy = data.aws_iam_policy_document.lambda_execution_policy[0].json
}

// Attach the base IAM policy.
resource "aws_iam_role_policy_attachment" "attach_base_policy" {
  count      = var.enabled
  role       = aws_iam_role.role[0].name
  policy_arn = var.base_policy_arn
}

// Create the Lambda log group.
resource "aws_cloudwatch_log_group" "lambda_log_group" {
  count             = var.enabled
  name              = "/aws/lambda/${var.function_name}"
  retention_in_days = var.log_retention_days

  tags = {
    Name = var.tagged_name
  }
}

// Create the Lambda function.
resource "aws_lambda_function" "function" {
  count = var.enabled

  function_name = var.function_name
  description   = var.description
  handler       = var.handler
  role          = aws_iam_role.role[0].arn
  runtime       = "python3.6"

  memory_size                    = var.memory_size_mb
  timeout                        = var.timeout_sec
  reserved_concurrent_executions = var.reserved_concurrent_executions

  filename         = var.filename
  source_code_hash = filebase64sha256(var.filename)
  publish          = true

  environment {
    variables = var.environment_variables
  }

  tags = {
    Name = var.tagged_name
  }
}

// Create a Production alias for each Lambda function.
resource "aws_lambda_alias" "production_alias" {
  count            = var.enabled
  name             = "Production"
  function_name    = aws_lambda_function.function[0].arn
  function_version = aws_lambda_function.function[0].version
}

// Alarm if the Lambda function has more than the configured number of errors.
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  count      = var.enabled
  alarm_name = "${var.function_name}_errors"

  alarm_description = <<EOF
${var.function_name} has a high error rate. Check the CloudWatch logs.
${var.alarm_errors_help}
EOF


  namespace   = "AWS/Lambda"
  metric_name = "Errors"
  statistic   = "Sum"

  dimensions = {
    FunctionName = aws_lambda_function.function[0].function_name
    Resource     = "${aws_lambda_function.function[0].function_name}:${aws_lambda_alias.production_alias[0].name}"
  }

  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = var.alarm_errors_threshold
  period              = var.alarm_errors_interval_secs
  evaluation_periods  = 1

  alarm_actions = var.alarm_sns_arns
}


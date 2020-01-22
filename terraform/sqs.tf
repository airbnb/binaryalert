// Analysis queue - S3 objects which need to be analyzed
resource "aws_sqs_queue" "analyzer_queue" {
  name                      = "${var.name_prefix}_binaryalert_analyzer_queue"
  kms_master_key_id         = aws_kms_key.sse_sqs.arn
  message_retention_seconds = var.analyze_queue_retention_secs

  // When a message is received, it will be invisible to other consumers for this long.
  // Set to just a few seconds after the lambda analyzer would timeout.
  visibility_timeout_seconds = format("%d", var.lambda_analyze_timeout_sec + 2)

  tags = {
    Name = var.tagged_name
  }
}

data "aws_iam_policy_document" "analyzer_queue_policy" {
  statement {
    sid = "AllowBinaryAlertBucketToNotifySQS"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.analyzer_queue.arn]

    // Allow only the BinaryAlert S3 bucket to notify the SQS queue.
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.binaryalert_binaries.arn]
    }
  }
}

// Allow analyzer queue to be sent messages from the BinaryAlert S3 bucket.
resource "aws_sqs_queue_policy" "analyzer_queue_policy" {
  queue_url = aws_sqs_queue.analyzer_queue.id
  policy    = data.aws_iam_policy_document.analyzer_queue_policy.json
}

// Downloader queue - MD5s to download from CarbonBlack
resource "aws_sqs_queue" "downloader_queue" {
  count                     = var.enable_carbon_black_downloader ? 1 : 0
  name                      = "${var.name_prefix}_binaryalert_downloader_queue"
  kms_master_key_id         = aws_kms_key.sse_sqs.arn
  message_retention_seconds = var.download_queue_retention_secs

  // When a message is received, it will be invisible to other consumers for this long.
  // Set to just a few seconds after the downloader would timeout.
  visibility_timeout_seconds = format("%d", var.lambda_download_timeout_sec + 2)

  // If a message fails to be processed after the set number of retries, it is delivered to the DLQ.
  redrive_policy = "{\"deadLetterTargetArn\":\"${aws_sqs_queue.dead_letter_queue[0].arn}\",\"maxReceiveCount\":${var.download_queue_max_receives}}"

  tags = {
    Name = var.tagged_name
  }
}

// Dead letter queue (DLQ) - messages which fail to be processed from SQS after X retries are sent here.
// Messages sent here are meant for human consumption (debugging) and are retained for 14 days.
// This is only used for the downloader queue (for now).
resource "aws_sqs_queue" "dead_letter_queue" {
  count                     = var.enable_carbon_black_downloader ? 1 : 0
  name                      = "${var.name_prefix}_binaryalert_sqs_dead_letter_queue"
  message_retention_seconds = 1209600

  kms_master_key_id = aws_kms_key.sse_sqs.arn

  tags = {
    Name = var.tagged_name
  }
}


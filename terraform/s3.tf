// S3 bucket for storing access logs.
resource "aws_s3_bucket" "binaryalert_log_bucket" {
  count = var.s3_log_bucket == "" ? 1 : 0 // Create only if no pre-existing log bucket.

  bucket = format(
    "%s-binaryalert-binaries-%s-access-logs",
    replace(var.name_prefix, "_", "-"),
    var.aws_region,
  )

  tags = {
    Name = var.tagged_name
  }

  force_destroy = var.force_destroy
}

// Policy for log bucket that forces ssl only access
data "aws_iam_policy_document" "force_ssl_only_access" {
  count = var.s3_log_bucket == "" ? 1 : 0 // Create only if no pre-existing log bucket.

  # Force SSL access only
  statement {
    sid = "ForceSSLOnlyAccess"

    effect = "Deny"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.binaryalert_log_bucket[0].arn,
      "${aws_s3_bucket.binaryalert_log_bucket[0].arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "force_ssl_only_access" {
  count = var.s3_log_bucket == "" ? 1 : 0 // Create only if no pre-existing log bucket.

  bucket = aws_s3_bucket.binaryalert_log_bucket[0].id
  policy = data.aws_iam_policy_document.force_ssl_only_access[0].json
}

// Source S3 bucket: binaries uploaded here will be automatically analyzed.
resource "aws_s3_bucket" "binaryalert_binaries" {
  bucket = "${replace(var.name_prefix, "_", "-")}-binaryalert-binaries-${var.aws_region}"

  tags = {
    Name = var.tagged_name
  }

  force_destroy = var.force_destroy
}

// Policy for source bucket that allows inventory delivery
data "aws_iam_policy_document" "allow_inventory" {
  statement {
    sid = "AllowSelfInventory"

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.binaryalert_binaries.arn}/inventory/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.aws_account_id]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.binaryalert_binaries.arn]
    }
  }

  # Force SSL access only
  statement {
    sid = "ForceSSLOnlyAccess"

    effect = "Deny"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.binaryalert_binaries.arn,
      "${aws_s3_bucket.binaryalert_binaries.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "allow_inventory" {
  bucket = aws_s3_bucket.binaryalert_binaries.id
  policy = data.aws_iam_policy_document.allow_inventory.json
}

// Enable bucket inventory
resource "aws_s3_bucket_inventory" "binary_inventory" {
  bucket = aws_s3_bucket.binaryalert_binaries.id
  name   = "EntireBucketDaily"

  included_object_versions = "Current"

  schedule {
    frequency = "Daily"
  }

  destination {
    bucket {
      format     = "CSV"
      bucket_arn = aws_s3_bucket.binaryalert_binaries.arn
      prefix     = "inventory"

      encryption {
        sse_kms {
          key_id = aws_kms_key.sse_s3.arn
        }
      }
    }
  }
}

// New objects uploaded for analysis notify the analyzer queue
resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.binaryalert_binaries.id

  queue {
    queue_arn = aws_sqs_queue.analyzer_queue.arn
    events    = ["s3:ObjectCreated:*"]
  }

  // The queue policy must be created before we can configure the S3 notification.
  depends_on = [aws_sqs_queue_policy.analyzer_queue_policy]
}

resource "aws_s3_bucket_accelerate_configuration" "binaryalert_binaries" {
  count  = var.s3_acceleration_enable == 0 ? 0 : 1
  bucket = aws_s3_bucket.binaryalert_binaries.bucket
  status = "Enabled"
}

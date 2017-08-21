// S3 bucket for storing access logs.
resource "aws_s3_bucket" "binaryalert_log_bucket" {
  count = "${var.s3_log_bucket == "" ? 1 : 0}" // Create only if no pre-existing log bucket.

  bucket = "${format("%s.binaryalert-binaries.%s.access-logs", replace(var.name_prefix, "_", "."), var.aws_region)}"
  acl    = "log-delivery-write"

  // Everything in the log bucket rotates to infrequent access and expires.
  lifecycle_rule {
    id      = "log_expiration"
    prefix  = ""
    enabled = true

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = "${var.s3_log_expiration_days}"
    }

    // Old/deleted object versions are permanently removed after 1 day.
    noncurrent_version_expiration {
      days = 1
    }
  }

  // Enable logging on the logging bucket itself.
  logging {
    // The target bucket is the same as the name of this bucket.
    target_bucket = "${format("%s.binaryalert-binaries.%s.access-logs", replace(var.name_prefix, "_", "."), var.aws_region)}"
    target_prefix = "self/"
  }

  tags {
    Name = "BinaryAlert"
  }

  // Enabling versioning protects against accidental deletes.
  versioning {
    enabled = true
  }
}

// Source S3 bucket: binaries uploaded here will be automatically analyzed.
resource "aws_s3_bucket" "binaryalert_binaries" {
  bucket = "${replace(var.name_prefix, "_", ".")}.binaryalert-binaries.${var.aws_region}"
  acl    = "private"

  logging {
    // Send S3 access logs to either the user-defined logging bucket or the one we created.
    // Note: We can't reference log bucket ID here becuase the bucket may not exist.
    target_bucket = "${var.s3_log_bucket == "" ?
      format("%s.binaryalert-binaries.%s.access-logs", replace(var.name_prefix, "_", "."), var.aws_region)
      : var.s3_log_bucket}"

    target_prefix = "${var.s3_log_prefix}"
  }

  // Note: STANDARD_IA is not worth it because of the need to periodically re-analyze all binaries
  // in the bucket.

  lifecycle_rule {
    id      = "delete_old_versions"
    prefix  = ""
    enabled = true

    // Old/deleted object versions are permanently removed after 1 day.
    noncurrent_version_expiration {
      days = 1
    }
  }

  tags {
    Name = "BinaryAlert"
  }

  versioning {
    enabled = true
  }
}

resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = "${aws_s3_bucket.binaryalert_binaries.id}"

  queue {
    queue_arn = "${aws_sqs_queue.s3_object_queue.arn}"
    events    = ["s3:ObjectCreated:*"]
  }

  // The queue policy must be created before we can configure the S3 notification.
  depends_on = ["aws_sqs_queue_policy.s3_object_queue_policy"]
}

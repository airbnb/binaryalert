// Allow S3 to encrypt with either SSE key (to encrypt inventory or to enqueue SQS)
data "aws_iam_policy_document" "kms_allow_s3" {
  statement {
    sid = "Enable IAM User Permissions"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.aws_account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid = "AllowS3ToUseKey"

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey*",
    ]

    resources = ["*"]
  }
}

// KMS key for server-side encryption (SSE) of S3
resource "aws_kms_key" "sse_s3" {
  description         = "BinaryAlert Server-Side Encryption - S3"
  enable_key_rotation = true

  tags = {
    Name = var.tagged_name
  }

  policy = data.aws_iam_policy_document.kms_allow_s3.json
}

resource "aws_kms_alias" "sse_s3_alias" {
  name          = "alias/${var.name_prefix}_binaryalert_sse_s3"
  target_key_id = aws_kms_key.sse_s3.key_id
}

// KMS key for server-side encryption (SSE) of SQS
resource "aws_kms_key" "sse_sqs" {
  description         = "BinaryAlert Server-Side Encryption - SQS"
  enable_key_rotation = true

  tags = {
    Name = var.tagged_name
  }

  policy = data.aws_iam_policy_document.kms_allow_s3.json
}

resource "aws_kms_alias" "sse_sqs_alias" {
  name          = "alias/${var.name_prefix}_binaryalert_sse_sqs"
  target_key_id = aws_kms_key.sse_sqs.key_id
}

// KMS key to encrypt CarbonBlack credentials
resource "aws_kms_key" "carbon_black_credentials" {
  count               = var.enable_carbon_black_downloader ? 1 : 0
  description         = "Encrypts CarbonBlack credentials for the BinaryAlert downloader."
  enable_key_rotation = true

  tags = {
    Name = var.tagged_name
  }
}

resource "aws_kms_alias" "encrypt_credentials_alias" {
  count         = var.enable_carbon_black_downloader ? 1 : 0
  name          = "alias/${var.name_prefix}_binaryalert_carbonblack_credentials"
  target_key_id = aws_kms_key.carbon_black_credentials[0].key_id
}


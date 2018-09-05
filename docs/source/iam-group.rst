Creating an IAM Group
=====================
When thinking about who on your team will be deploying BinaryAlert, we recommend creating an IAM
group with least-privilege permissions and adding users to that group.

The following is an example Terraform file that can be applied by an account admin outside of the
BinaryAlert repo to create a least-privilege group. This group will have permission to create,
modify, and destroy all of the BinaryAlert infrastructure:

::

    # ========== Variables ==========

    variable "account" {
      default = "123412341234"  # Replace with your account ID
    }

    variable "region" {
      default = "us-east-1"  # Region in which BinaryAlert will be deployed
    }

    variable "prefix" {
      default = "binaryalert-prefix"  # The name prefix you will use when deploying BinaryAlert
    }

    # ========== IAM policy ==========

    data "aws_iam_policy_document" "binaryalert_admin" {
      statement {
        effect = "Allow"

        actions = [
          "cloudwatch:DeleteAlarms",
          "cloudwatch:DeleteDashboards",
          "cloudwatch:DescribeAlarms",
          "cloudwatch:PutMetricAlarm",
        ]

        resources = ["*"]
      }

      statement {
        effect    = "Allow"
        actions   = ["cloudwatch:*"]
        resources = ["arn:aws:cloudwatch::${var.account}:dashboard/BinaryAlert"]
      }

      statement {
        effect    = "Allow"
        actions   = ["dynamodb:*"]
        resources = ["arn:aws:dynamodb:${var.region}:${var.account}:table/${var.prefix}_binaryalert*"]
      }

      statement {
        effect    = "Allow"
        actions   = ["events:*"]
        resources = ["arn:aws:events:${var.region}:${var.account}:rule/${var.prefix}_binaryalert*"]
      }

      statement {
        effect  = "Allow"
        actions = ["iam:*"]

        resources = [
          "arn:aws:iam::${var.account}:policy/${var.prefix}_binaryalert*",
          "arn:aws:iam::${var.account}:role/${var.prefix}_binaryalert*",
        ]
      }

      statement {
        effect = "Allow"

        actions = [
          "iam:Get*",
          "iam:List*",
        ]

        resources = ["*"]
      }

      statement {
        effect = "Allow"

        actions = [
          "kms:CreateKey",
          "kms:Describe*",
          "kms:Get*",
          "kms:List*",
        ]

        resources = ["*"]
      }

      statement {
        effect  = "Allow"
        actions = ["kms:*"]

        resources = [
          "arn:aws:kms:${var.region}:${var.account}:alias/${var.prefix}_binaryalert*",

          # NOTE: For each new key that is generated, add permissions to use that key here:
          # "arn:aws:kms:${var.region}:${var.account}:key/KEY-UUID",
        ]
      }

      statement {
        effect    = "Allow"
        actions   = ["lambda:*"]
        resources = ["arn:aws:lambda:${var.region}:${var.account}:function:${var.prefix}_binaryalert*"]
      }

      statement {
        effect = "Allow"

        actions = [
          "logs:Describe*",
          "logs:Get*",
          "logs:List*",
        ]

        resources = ["*"]
      }

      statement {
        effect    = "Allow"
        actions   = ["logs:*"]
        resources = ["arn:aws:logs:${var.region}:${var.account}:log-group:/aws/lambda/${var.prefix}_binaryalert*"]
      }

      statement {
        effect    = "Allow"
        actions   = ["s3:*"]
        resources = ["arn:aws:s3:::${replace(var.prefix, "_", ".")}.binaryalert*"]
      }

      statement {
        effect    = "Allow"
        actions   = ["sns:*"]
        resources = ["arn:aws:sns:${var.region}:${var.account}:${var.prefix}_binaryalert*"]
      }

      statement {
        effect    = "Allow"
        actions   = ["sqs:*"]
        resources = ["arn:aws:sqs:${var.region}:${var.account}:${var.prefix}_binaryalert*"]
      }
    }

    resource "aws_iam_policy" "binaryalert_admin" {
      name        = "binaryalert_admin_policy"
      description = "Policy for managing BinaryAlert"
      policy      = "${data.aws_iam_policy_document.binaryalert_admin.json}"
    }


    # ========== IAM Group ==========

    resource "aws_iam_group" "binaryalert_admin" {
      name = "BinaryAlertAdmin"
    }

    resource "aws_iam_group_policy_attachment" "custom_policy" {
      group      = "${aws_iam_group.binaryalert_admin.name}"
      policy_arn = "${aws_iam_policy.binaryalert_admin.arn}"
    }

Once you ``terraform apply`` to create the IAM group, you can add new or existing users to the group
(manually or with Terraform).
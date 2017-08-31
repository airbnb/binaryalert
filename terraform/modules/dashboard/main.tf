// CloudWatch dashboard for BinaryAlert
// Due to https://github.com/hashicorp/terraform/issues/15969,
// locals only work in single-file modules for the time being.
// This is why the dashboard is in its own module.

variable "aws_region" {}

locals {
  analyzed_binaries = ["BinaryAlert", "AnalyzedBinaries"]
  matched_binaries  = ["BinaryAlert", "MatchedBinaries"]

  dashboard_body = {
    widgets = [
      {
        type  = "metric"
        width = 12

        properties = {
          title  = "Analyzed Binaries"
          region = "${var.aws_region}"
          stat   = "Sum"
          period = 300

          // Due to https://github.com/hashicorp/terraform/issues/15971,
          // nested lists must be constructed with the "list" command instead of [] notation.
          metrics = "${list(local.analyzed_binaries, local.matched_binaries)}"
        }
      },
    ]
  }
}

resource "aws_cloudwatch_dashboard" "binaryalert" {
  dashboard_name = "BinaryAlert"

  // Encode to JSON and remove quotes around numbers.
  dashboard_body = "${replace(jsonencode(local.dashboard_body), "/\"(\\d+)\"/", "$1")}"
}

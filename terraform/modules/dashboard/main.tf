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
          // nested lists are flattened during jsonencoding. That won't work here,
          // so we json-encode each nested list as a string and use string replacements
          // to remove the extra quotes and make them a real nested list.
          metrics = [
            "${jsonencode(local.analyzed_binaries)}",
            "${jsonencode(local.matched_binaries)}",
          ]
        }
      },
    ]
  }
}

locals {
  // Un-stringify the nested lists.
  replace1               = "${replace(jsonencode(local.dashboard_body), "\"[", "[")}"
  replace2               = "${replace(local.replace1, "\\", "")}"
  nested_list_correction = "${replace(local.replace2, "\"]\"", "\"]")}"

  // Numbers must be numbers, not strings (uses regex capture group).
  number_replace = "${replace(local.nested_list_correction, "/\"(\\d+)\"/", "$1")}"
}

resource "aws_cloudwatch_dashboard" "binaryalert" {
  dashboard_name = "BinaryAlert"
  dashboard_body = "${local.number_replace}"
}

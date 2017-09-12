terraform {
  // 0.10.4 is required for locals to work correctly across multiple files
  required_version = "~> 0.10.4"
}

provider "aws" {
  // 0.1.4 required for aws_cloudwatch_dashboard
  version = "~> 0.1.4"
  region  = "${var.aws_region}"
}

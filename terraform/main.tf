terraform {
  // 0.10.1 includes important bug fixes for remote backends
  required_version = "~> 0.10.1"
}

provider "aws" {
  // 0.1.4 required for aws_cloudwatch_dashboard
  version = "~> 0.1.4"
  region  = "${var.aws_region}"
}

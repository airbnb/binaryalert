terraform {
  // 0.10.3 required for locals
  required_version = "~> 0.10.3"
}

provider "aws" {
  // 0.1.4 required for aws_cloudwatch_dashboard
  version = "~> 0.1.4"
  region  = "${var.aws_region}"
}

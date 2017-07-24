provider "aws" {
  region = "${var.aws_region}"
}

terraform {
  required_version = "~> 0.9.6"
}

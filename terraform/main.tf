terraform {
  required_version = "~> 0.11.0"
}

provider "aws" {
  version = "~> 1.3.1"
  region  = "${var.aws_region}"
}

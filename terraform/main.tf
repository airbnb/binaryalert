terraform {
  required_version = "~> 0.11.2"
}

provider "aws" {
  version = "~> 1.14.1"
  region  = "${var.aws_region}"
}

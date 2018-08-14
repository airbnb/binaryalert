terraform {
  required_version = "~> 0.11.7"
}

provider "aws" {
  version = "~> 1.30.0"
  region  = "${var.aws_region}"
}

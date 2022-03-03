provider "aws" {
  version = "~> 4.0.0"
  region  = var.aws_region
  profile = "default"
}

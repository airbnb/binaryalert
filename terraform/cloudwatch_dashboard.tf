module "binaryalert_dashboard" {
  source     = "modules/dashboard"
  aws_region = "${var.aws_region}"
}

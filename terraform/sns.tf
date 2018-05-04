// YARA match alerts will be published to this SNS topic.
resource "aws_sns_topic" "yara_match_alerts" {
  name = "${var.name_prefix}_binaryalert_yara_match_alerts"
}

// CloudWatch metric alarms notify this SNS topic.
resource "aws_sns_topic" "metric_alarms" {
  name = "${var.name_prefix}_binaryalert_metric_alarms"
}

//No YARA match alerts will be published to this SNS topic.
resource "aws_sns_topic" "safe_alerts" {
  count = "${var.enable_safe_alerts}"
  name  = "${var.name_prefix}_binaryalert_safe_alerts"
}

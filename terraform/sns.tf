// YARA match alerts will be published to this SNS topic.
resource "aws_sns_topic" "yara_match_alerts" {
  name = "${var.name_prefix}_binaryalert_yara_match_alerts"
}

// If a file does NOT match any YARA rules, notify this SNS topic.
resource "aws_sns_topic" "no_yara_match" {
  count = var.enable_negative_match_alerts ? 1 : 0
  name  = "${var.name_prefix}_binaryalert_no_yara_match"
}

// CloudWatch metric alarms notify this SNS topic (created only if an existing one is not specified)
resource "aws_sns_topic" "metric_alarms" {
  count = var.metric_alarm_sns_topic_arn == "" ? 1 : 0
  name  = "${var.name_prefix}_binaryalert_metric_alarms"
}


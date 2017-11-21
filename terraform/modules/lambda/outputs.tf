# All outputs are conditionally defined based on whether the underlying resources exist (count > 0)
# https://www.terraform.io/upgrade-guides/0-11.html#referencing-attributes-from-resources-with-count-0

output "alias_arn" {
  value = "${element(concat(aws_lambda_alias.production_alias.*.arn, list("")), 0)}"
}

output "alias_name" {
  value = "${element(concat(aws_lambda_alias.production_alias.*.name, list("")), 0)}"
}

output "function_arn" {
  value = "${element(concat(aws_lambda_function.function.*.arn, list("")), 0)}"
}

output "function_name" {
  value = "${element(concat(aws_lambda_function.function.*.function_name, list("")), 0)}"
}

output "log_group_name" {
  value = "${element(concat(aws_cloudwatch_log_group.lambda_log_group.*.name, list("")), 0)}"
}

output "role_id" {
  value = "${element(concat(aws_iam_role.role.*.id, list("")), 0)}"
}

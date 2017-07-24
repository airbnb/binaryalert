output "alias_arn" {
  value = "${aws_lambda_alias.production_alias.arn}"
}

output "alias_name" {
  value = "${aws_lambda_alias.production_alias.name}"
}

output "function_arn" {
  value = "${aws_lambda_function.function.arn}"
}

output "function_name" {
  value = "${aws_lambda_function.function.function_name}"
}

output "role_id" {
  value = "${aws_iam_role.role.id}"
}

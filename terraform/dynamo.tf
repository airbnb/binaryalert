// DynamoDB table for storing match results.
resource "aws_dynamodb_table" "binaryalert_yara_matches" {
  name           = "${var.name_prefix}_binaryalert_matches"
  hash_key       = "SHA256"
  range_key      = "LambdaVersion"
  read_capacity  = "${var.dynamo_read_capacity}"
  write_capacity = "${var.dynamo_write_capacity}"

  // Only attributes used as hash/range keys are defined here.
  attribute {
    name = "SHA256"
    type = "S"
  }

  attribute {
    name = "LambdaVersion"
    type = "N"
  }

  tags {
    Name = "BinaryAlert"
  }
}

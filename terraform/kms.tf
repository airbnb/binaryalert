/* Create a KMS key to encrypt/decrypt CarbonBlack credentials. */

resource "aws_kms_key" "carbon_black_credentials" {
  count               = "${var.enable_carbon_black_downloader}"
  description         = "Encrypts CarbonBlack credentials for the BinaryAlert downloader."
  enable_key_rotation = true

  tags {
    Name = "BinaryAlert"
  }
}

resource "aws_kms_alias" "encrypt_credentials_alias" {
  count         = "${var.enable_carbon_black_downloader}"
  name          = "alias/${var.name_prefix}_binaryalert_carbonblack_credentials"
  target_key_id = "${aws_kms_key.carbon_black_credentials.key_id}"
}

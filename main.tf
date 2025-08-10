provider "aws" {
  region = "us-east-1"
}

# Insecure S3 bucket: triggers CKV_AWS_21, CKV_AWS_145, CKV2_AWS_6, CKV2_AWS_62, CKV_AWS_144, CKV_AWS_18, CKV2_AWS_61
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-insecure-secure-bucket"
  acl    = "private"
}

# Intentionally missing:
# - versioning
# - kms encryption
# - public access block
# - event notifications
# - cross-region replication
# - access logging
# - lifecycle configuration

provider "aws" {
  region = "us-east-1"
}

# S3 bucket with all the specific misconfigs for your 8 checks
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-demo-insecure-bucket"
  acl    = "private" # not public, but missing required configs

  tags = {
    Environment = "Dev"
    Project     = "IaC Security Gatekeeper"
  }
}

# Note: Intentionally omitting:
# - Access logging (CKV_AWS_18)
# - Server-side encryption (CKV_AWS_19)
# - Public access block (CKV_AWS_20)
# - Versioning (CKV_AWS_21)
# - SSL-only policy (CKV_AWS_22)
# - Cross-region replication (CKV_AWS_28)
# - Event notifications (CKV_AWS_29)
# - Lifecycle policy (CKV_AWS_30)

provider "aws" {
  region = "us-east-1"
}

# Secure S3 bucket
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-demo-bucket"
  acl    = "private"

  tags = {
    Environment = "Dev"
    Project     = "IaC Security Gatekeeper"
  }
}

# Enable versioning
resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.secure_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

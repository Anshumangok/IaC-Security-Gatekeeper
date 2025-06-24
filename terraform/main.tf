provider "aws" {
  region = "us-east-1"
}

# ❌ Misconfigured public S3 bucket (Checkov should flag this)
resource "aws_s3_bucket" "public_bucket_1" {
  bucket = "my-public-bucket-1"
  acl    = "public-read"

  tags = {
    Name        = "Public Bucket 1"
    Environment = "Test"
  }
}

# ❌ Another misconfigured bucket with public-write
resource "aws_s3_bucket" "public_bucket_2" {
  bucket = "my-public-bucket-2"
  acl    = "public-write"

  tags = {
    Name        = "Public Bucket 2"
    Environment = "Test"
  }
}

# ✅ Correctly configured bucket (will remain untouched)
resource "aws_s3_bucket" "private_bucket" {
  bucket = "my-private-bucket"
  acl    = "private"

  tags = {
    Name        = "Private Bucket"
    Environment = "Prod"
  }
}

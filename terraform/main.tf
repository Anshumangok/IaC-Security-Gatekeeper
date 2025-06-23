resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket-checkov"
  force_destroy = true

  tags = {
    Name        = "SecureBucket"
    Environment = "Prod"
  }
}

resource "aws_s3_bucket_versioning" "enabled" {
  bucket = aws_s3_bucket.secure_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure_bucket.bucket

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "alias/aws/s3"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "secure" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "secure" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    id     = "log"
    status = "Enabled"

    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket_logging" "log" {
  bucket = aws_s3_bucket.secure_bucket.id

  target_bucket = "my-secure-log-bucket"
  target_prefix = "log/"
}

resource "aws_s3_bucket_notification" "notification" {
  bucket = aws_s3_bucket.secure_bucket.id

  lambda_function {
    lambda_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:my-function"
    events              = ["s3:ObjectCreated:*"]
  }
}

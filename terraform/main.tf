resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket"

  versioning {
    enabled = true
  }

  logging {
    target_bucket = "log-bucket"
    target_prefix = "log/"
  }

  lifecycle {
    rule {
      id      = "expire-logs"
      enabled = true
      expiration {
        days = 30
      }
    }
  }

  replication_configuration {
    role = "arn:aws:iam::123456789012:role/replication-role"
    rules {
      id     = "replication-rule"
      status = "Enabled"

      destination {
        bucket        = "arn:aws:s3:::destination-bucket"
        storage_class = "STANDARD"
      }
    }
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = "alias/aws/s3"
        sse_algorithm     = "aws:kms"
      }
    }
  }

  tags = {
    Name        = "Secure Bucket"
    Environment = "Prod"
  }
}

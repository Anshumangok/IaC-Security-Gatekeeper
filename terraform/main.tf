provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "public_bucket" {
  bucket = "test-insecure-bucket-anshuman"
  acl    = "public-read"  # ❌ PUBLIC ACL (Misconfigured)

  tags = {
    Name        = "Insecure Bucket"
    Environment = "Dev"
  }
}
resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.public_bucket.id

  versioning_configuration {
    status = "Suspended"  # ❌ Versioning disabled (optional best-practice issue)
  }
}

resource "aws_s3_bucket_policy" "allow_all" {
  bucket = aws_s3_bucket.public_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.public_bucket.arn}/*"
      }
    ]
  })  # ❌ Open access policy
}
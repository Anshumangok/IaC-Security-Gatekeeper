resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket"
  acl    = "public-read"  # ❌ This is insecure and will be flagged

  tags = {
    Name        = "Public Bucket"
    Environment = "Dev"
  }
}

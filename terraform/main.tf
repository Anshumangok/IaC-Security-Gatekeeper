resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-test-public-bucket-v4"
  acl    = "public-read"

  tags = {
    Name        = "Public Bucket"
    Environment = "Dev"
  }
}

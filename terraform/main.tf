# Triggering Checkov scan
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-test-public-bucket-v5" #Misconfigured
  acl    = "public-read"

  tags = {
    Name        = "Public Bucket"
    Environment = "Dev"
  }
}

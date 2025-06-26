# Sample misconfigured S3 bucket for testing
resource "aws_s3_bucket" "example" {
  bucket = "my-public-bucket"
  acl    = "public-read"

  tags = {
    environment = "dev"
  }
}

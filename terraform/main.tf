resource "aws_s3_bucket" "test" {
  bucket = "my-insecure-bucket"
  acl    = "public-read"

  tags = {
    Environment = "dev"
  }
}

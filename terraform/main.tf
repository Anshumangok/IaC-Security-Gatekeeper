# test-s3.tf
resource "aws_s3_bucket" "test" {
  bucket = "my-test-bucket"
  acl    = "public-read"  # This will trigger security issues
}
resource "aws_s3_bucket" "unsecure_bucket" {
  bucket = "example-insecure-bucket"
  acl    = "public-read"
}

resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}
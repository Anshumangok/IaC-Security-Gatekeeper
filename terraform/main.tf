resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}
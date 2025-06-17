resource "aws_s3_bucket" "example" {
   acl    = "public-read"
   bucket = "my-insecure-bucket # ❌ Misconfigured
}

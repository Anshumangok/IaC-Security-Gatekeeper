resource "aws_s3_bucket" "test" {
  bucket = "my-vulnerable-test-bucket"
  acl    = "public-read"
  
  tags = {
    Name        = "Test Bucket"
    Environment = "Dev"
  }
}
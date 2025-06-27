terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

# 1. Public S3 bucket with public-read ACL (CKV_AWS_20)
resource "aws_s3_bucket" "public_bucket_1" {
  bucket = "my-public-test-bucket-123456"
}
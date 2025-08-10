provider "aws" {
  region = "us-east-1"
}

# ✅ Secure S3 bucket with best practices
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket-demo"
  acl    = "private"

  tags = {
    Environment = "Dev"
    Project     = "IaC Security Gatekeeper"
  }
}

resource "aws_s3_bucket_versioning" "secure_versioning" {
  bucket = aws_s3_bucket.secure_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_encryption" {
  bucket = aws_s3_bucket.secure_bucket.bucket

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ✅ Security group with restricted access
resource "aws_security_group" "secure_sg" {
  name        = "secure_sg"
  description = "Allow SSH from specific IP"
  vpc_id      = "vpc-12345678"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.25/32"] # specific IP only
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ✅ IAM user with MFA
resource "aws_iam_user" "dev_user" {
  name = "developer-user"
  tags = {
    Team = "DevOps"
  }
}

resource "aws_iam_user_login_profile" "dev_user_profile" {
  user    = aws_iam_user.dev_user.name
  pgp_key = "keybase:example" # Replace with your real PGP key
}

# ✅ EC2 instance with secure settings
resource "aws_instance" "secure_instance" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  tags = {
    Name = "SecureInstance"
  }
}

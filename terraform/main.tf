provider "aws" {
  region = "us-east-1"
}

# ❌ S3 bucket: Public and unencrypted
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-insecure-bucket"
  acl    = "public-read"  # CKV_AWS_20

  tags = {
    Name = "PublicBucket"
  }
}

resource "aws_s3_bucket_public_access_block" "insecure_block" {
  bucket = aws_s3_bucket.public_bucket.id

  block_public_acls       = false  # CKV2_AWS_6
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}

# ❌ IAM policy allows wildcard actions and resources
resource "aws_iam_policy" "bad_policy" {
  name        = "AllowAllPolicy"
  description = "Bad policy with wildcards"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*",              # CKV_AWS_117
        Effect   = "Allow",
        Resource = "*"
      }
    ]
  })
}

# ❌ Security group: open to the world
resource "aws_security_group" "open_sg" {
  name        = "open-sg"
  description = "Allow all inbound traffic"
  vpc_id      = "vpc-123456"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]     # CKV_AWS_23
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ❌ RDS instance: not encrypted, publicly accessible
resource "aws_db_instance" "bad_rds" {
  identifier        = "bad-rds"
  engine            = "mysql"
  instance_class    = "db.t2.micro"
  username          = "admin"
  password          = "plain-text-password"   # CKV_AWS_79
  publicly_accessible = true                  # CKV_AWS_16
  allocated_storage = 20
  skip_final_snapshot = true
}

# ❌ EC2 instance: missing detailed monitoring and security group
resource "aws_instance" "unhardened_ec2" {
  ami           = "ami-0c94855ba95c71c99"  # Replace with a valid public AMI for your region
  instance_type = "t2.micro"

  tags = {
    Name = "InsecureEC2"
  }
}

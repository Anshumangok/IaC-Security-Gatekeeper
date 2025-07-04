provider "aws" {
  region = "us-east-1"
}

# ✅ S3 bucket: private, encrypted, access logging enabled
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "secure-compliant-bucket"
  acl    = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  versioning {
    enabled = true
  }

  tags = {
    Name        = "SecureBucket"
    Environment = "prod"
  }
}

resource "aws_s3_bucket_public_access_block" "secure_block" {
  bucket                  = aws_s3_bucket.secure_bucket.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "secure_logging" {
  bucket        = aws_s3_bucket.secure_bucket.id
  target_bucket = aws_s3_bucket.secure_bucket.id
  target_prefix = "log/"
}

# ✅ IAM policy: least privilege, no wildcards
resource "aws_iam_policy" "read_only_s3" {
  name        = "ReadOnlyS3Policy"
  description = "Allow read-only access to S3 bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["s3:GetObject"],
        Effect   = "Allow",
        Resource = "${aws_s3_bucket.secure_bucket.arn}/*"
      }
    ]
  })
}

# ✅ Security group: only allow HTTPS from internal network
resource "aws_security_group" "secure_sg" {
  name   = "secure-sg"
  vpc_id = "vpc-123456"  # Replace with your real VPC ID

  ingress {
    description = "HTTPS from internal network"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "SecureSG"
  }
}

# ✅ RDS instance: encrypted, private, no hardcoded secrets
resource "aws_db_instance" "secure_rds" {
  identifier           = "secure-db"
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  username             = var.db_user
  password             = var.db_password
  allocated_storage    = 20
  storage_encrypted    = true
  publicly_accessible  = false
  skip_final_snapshot  = true

  vpc_security_group_ids = [aws_security_group.secure_sg.id]

  tags = {
    Name = "SecureRDS"
  }
}

# ✅ EC2 instance: monitored, private, no public IP
resource "aws_instance" "secure_ec2" {
  ami                         = "ami-0c94855ba95c71c99"  # Replace with valid secure AMI
  instance_type               = "t2.micro"
  monitoring                  = true
  associate_public_ip_address = false

  vpc_security_group_ids = [aws_security_group.secure_sg.id]

  tags = {
    Name = "SecureEC2"
  }
}

# ✅ Variables (no hardcoded secrets)
variable "db_user" {
  type        = string
  description = "RDS DB username"
}

variable "db_password" {
  type        = string
  description = "RDS DB password"
  sensitive   = true
}

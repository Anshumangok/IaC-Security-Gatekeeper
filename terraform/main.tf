provider "aws" {
  region = "us-east-1"
}

variable "db_user" {
  type        = string
  description = "RDS DB username"
}

variable "db_password" {
  type        = string
  description = "RDS DB password"
  sensitive   = true
}

# ✅ Secure S3 bucket
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "lean-secure-bucket"
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

# ✅ Secure security group — limited egress
resource "aws_security_group" "secure_sg" {
  name   = "secure-sg"
  vpc_id = "vpc-123456" # Replace with your actual VPC ID

  ingress {
    description = "Allow HTTPS from internal network"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    description = "Allow all egress (justified)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "SecureSG"
  }
}

# ✅ Secure EC2
resource "aws_iam_role" "ec2_role" {
  name = "ec2-secure-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_instance" "secure_ec2" {
  ami                         = "ami-0c94855ba95c71c99"  # Use a valid public AMI
  instance_type               = "t3.micro"
  monitoring                  = true
  associate_public_ip_address = false
  ebs_optimized               = true

  vpc_security_group_ids = [aws_security_group.secure_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name

  root_block_device {
    encrypted = true
  }

  tags = {
    Name = "SecureEC2"
  }
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2-secure-profile"
  role = aws_iam_role.ec2_role.name
}

# ✅ Secure RDS
resource "aws_db_instance" "secure_rds" {
  identifier                   = "secure-db"
  engine                       = "mysql"
  instance_class               = "db.t3.micro"
  username                     = var.db_user
  password                     = var.db_password
  allocated_storage            = 20
  storage_encrypted            = true
  publicly_accessible          = false
  skip_final_snapshot          = true
  backup_retention_period      = 7
  monitoring_interval          = 60
  auto_minor_version_upgrade   = true
  iam_database_authentication_enabled = false
  storage_type                 = "gp3"
  enabled_cloudwatch_logs_exports    = ["error", "general", "slowquery", "audit"]

  vpc_security_group_ids = [aws_security_group.secure_sg.id]

  tags = {
    Name = "SecureRDS"
  }
}

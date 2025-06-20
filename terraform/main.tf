# Terraform configuration with intentional security misconfigurations
# This file will trigger multiple Checkov security checks

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

# S3 Bucket with multiple security issues
resource "aws_s3_bucket" "example_bucket" {
  bucket = "my-insecure-bucket-12345"
  
  # MISCONFIGURATION: No versioning enabled
  # MISCONFIGURATION: No encryption specified
}

# Public S3 bucket (CRITICAL security issue)
resource "aws_s3_bucket_public_access_block" "example_bucket_pab" {
  bucket = aws_s3_bucket.example_bucket.id

  # MISCONFIGURATION: Allowing public access
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Security Group with overly permissive rules
resource "aws_security_group" "web_sg" {
  name_prefix = "web-sg"
  description = "Security group for web servers"

  # MISCONFIGURATION: SSH open to the world (0.0.0.0/0)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access from anywhere"
  }

  # MISCONFIGURATION: HTTP open to the world
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP access from anywhere"
  }

  # MISCONFIGURATION: All outbound traffic allowed
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }
}

# EC2 Instance with security issues
resource "aws_instance" "web_server" {
  ami           = "ami-0c02fb55956c7d316" # Amazon Linux 2
  instance_type = "t2.micro"
  
  # MISCONFIGURATION: No encryption for EBS root volume
  # MISCONFIGURATION: No IMDSv2 enforcement
  # MISCONFIGURATION: Public IP assigned
  associate_public_ip_address = true
  
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  
  # MISCONFIGURATION: User data with hardcoded secrets
  user_data = <<-EOF
    #!/bin/bash
    export DB_PASSWORD="hardcoded-password-123"
    export API_KEY="sk-1234567890abcdef"
    yum update -y
    yum install -y httpd
    systemctl start httpd
    systemctl enable httpd
  EOF

  tags = {
    Name = "WebServer"
  }
}

# RDS Database with security issues
resource "aws_db_instance" "database" {
  identifier = "myapp-database"
  
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"
  
  allocated_storage = 20
  storage_type      = "gp2"
  
  # MISCONFIGURATION: Database publicly accessible
  publicly_accessible = true
  
  # MISCONFIGURATION: No encryption at rest
  storage_encrypted = false
  
  # MISCONFIGURATION: Weak database credentials
  db_name  = "myapp"
  username = "admin"
  password = "password123"  # Hardcoded password
  
  # MISCONFIGURATION: No backup retention
  backup_retention_period = 0
  
  # MISCONFIGURATION: Skip final snapshot
  skip_final_snapshot = true
  
  # MISCONFIGURATION: No deletion protection
  deletion_protection = false
  
  vpc_security_group_ids = [aws_security_group.db_sg.id]
}

# Database Security Group with issues
resource "aws_security_group" "db_sg" {
  name_prefix = "db-sg"
  description = "Security group for database"

  # MISCONFIGURATION: Database port open to the world
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "MySQL access from anywhere"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# IAM Role with overly broad permissions
resource "aws_iam_role" "app_role" {
  name = "app-role"

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

# MISCONFIGURATION: Overly permissive IAM policy
resource "aws_iam_role_policy" "app_policy" {
  name = "app-policy"
  role = aws_iam_role.app_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # MISCONFIGURATION: Wildcard permissions on all resources
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# Load Balancer without security features
resource "aws_lb" "app_lb" {
  name               = "app-load-balancer"
  internal           = false
  load_balancer_type = "application"
  
  # MISCONFIGURATION: No access logs enabled
  # MISCONFIGURATION: No deletion protection
  enable_deletion_protection = false
  
  security_groups = [aws_security_group.web_sg.id]
  
  # Note: subnets would be required in real scenario
}

# CloudWatch Log Group without encryption
resource "aws_cloudwatch_log_group" "app_logs" {
  name = "/aws/ec2/app"
  
  # MISCONFIGURATION: No encryption specified
  # MISCONFIGURATION: No retention period set (logs kept forever)
}
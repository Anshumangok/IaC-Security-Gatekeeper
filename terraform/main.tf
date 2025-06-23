# Secure Terraform configuration that passes Checkov security checks
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

# Data source for current caller identity
data "aws_caller_identity" "current" {}

# S3 Bucket with comprehensive security configuration
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket-${random_id.bucket_suffix.hex}"

  tags = {
    Name        = "Secure Bucket"
    Environment = "Production"
  }
}

# Random ID for unique bucket naming
resource "random_id" "bucket_suffix" {
  byte_length = 8
}

# S3 Bucket Versioning
resource "aws_s3_bucket_versioning" "secure_bucket_versioning" {
  bucket = aws_s3_bucket.secure_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 Bucket Server Side Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_bucket_encryption" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.s3_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# KMS Key for S3 encryption
resource "aws_kms_key" "s3_key" {
  description             = "KMS key for S3 bucket encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "S3-Encryption-Key"
  }
}

# KMS Key Alias
resource "aws_kms_alias" "s3_key_alias" {
  name          = "alias/s3-encryption-key"
  target_key_id = aws_kms_key.s3_key.key_id
}

# S3 Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "secure_bucket_pab" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 Bucket Lifecycle Configuration
resource "aws_s3_bucket_lifecycle_configuration" "secure_bucket_lifecycle" {
  depends_on = [aws_s3_bucket_versioning.secure_bucket_versioning]
  bucket     = aws_s3_bucket.secure_bucket.id

  rule {
    id     = "secure_lifecycle_rule"
    status = "Enabled"

    expiration {
      days = 90
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# S3 Bucket Logging
resource "aws_s3_bucket" "access_logs_bucket" {
  bucket = "access-logs-${random_id.bucket_suffix.hex}"

  tags = {
    Name = "Access Logs Bucket"
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs_bucket_pab" {
  bucket = aws_s3_bucket.access_logs_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs_bucket_encryption" {
  bucket = aws_s3_bucket.access_logs_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_logging" "secure_bucket_logging" {
  bucket = aws_s3_bucket.secure_bucket.id

  target_bucket = aws_s3_bucket.access_logs_bucket.id
  target_prefix = "access-logs/"
}

# S3 Bucket Notification Configuration
resource "aws_s3_bucket_notification" "secure_bucket_notification" {
  bucket = aws_s3_bucket.secure_bucket.id

  eventbridge = true
}

# Security Group with restrictive rules
resource "aws_security_group" "secure_web_sg" {
  name_prefix = "secure-web-sg"
  description = "Secure security group for web servers"

  # HTTPS only from specific CIDR
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
    description = "HTTPS access from private network"
  }

  # HTTP only from specific CIDR
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
    description = "HTTP access from private network"
  }

  # Restrictive outbound rules
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS outbound"
  }

  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP outbound"
  }

  tags = {
    Name = "Secure Web Security Group"
  }
}

# EC2 Instance with security hardening
resource "aws_instance" "secure_web_server" {
  ami           = "ami-0c02fb55956c7d316" # Amazon Linux 2
  instance_type = "t3.micro"
  
  # Security configurations
  associate_public_ip_address = false
  monitoring                  = true
  
  vpc_security_group_ids = [aws_security_group.secure_web_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name
  
  # EBS encryption
  root_block_device {
    encrypted   = true
    kms_key_id  = aws_kms_key.ebs_key.arn
    volume_type = "gp3"
  }

  # IMDSv2 enforcement
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  # Secure user data without hardcoded secrets
  user_data = base64encode(<<-EOF
    #!/bin/bash
    yum update -y
    yum install -y httpd awscli
    
    # Get secrets from AWS Systems Manager Parameter Store
    DB_PASSWORD=$(aws ssm get-parameter --name "/app/db/password" --with-decryption --query 'Parameter.Value' --output text --region us-west-2)
    API_KEY=$(aws ssm get-parameter --name "/app/api/key" --with-decryption --query 'Parameter.Value' --output text --region us-west-2)
    
    systemctl start httpd
    systemctl enable httpd
  EOF
  )

  tags = {
    Name = "Secure Web Server"
  }
}

# KMS Key for EBS encryption
resource "aws_kms_key" "ebs_key" {
  description             = "KMS key for EBS encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name = "EBS-Encryption-Key"
  }
}

# IAM Role with minimal permissions
resource "aws_iam_role" "ec2_role" {
  name = "secure-ec2-role"

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

  tags = {
    Name = "Secure EC2 Role"
  }
}

# IAM Policy with specific permissions
resource "aws_iam_role_policy" "ec2_policy" {
  name = "secure-ec2-policy"
  role = aws_iam_role.ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters"
        ]
        Resource = [
          "arn:aws:ssm:us-west-2:${data.aws_caller_identity.current.account_id}:parameter/app/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:us-west-2:${data.aws_caller_identity.current.account_id}:*"
      }
    ]
  })
}

# IAM Instance Profile
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "secure-ec2-profile"
  role = aws_iam_role.ec2_role.name
}

# Secure RDS Database
resource "aws_db_instance" "secure_database" {
  identifier = "secure-myapp-database"
  
  engine         = "mysql"
  engine_version = "8.0.35"
  instance_class = "db.t3.micro"
  
  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id           = aws_kms_key.rds_key.arn
  
  # Security configurations
  publicly_accessible = false
  
  db_name  = "myapp"
  username = "admin"
  manage_master_user_password = true
  
  # Backup and maintenance
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  # Security and monitoring
  deletion_protection = true
  skip_final_snapshot = false
  final_snapshot_identifier = "secure-myapp-database-final-snapshot"
  
  performance_insights_enabled = true
  monitoring_interval         = 60
  monitoring_role_arn        = aws_iam_role.rds_monitoring_role.arn
  
  enabled_cloudwatch_logs_exports = ["error", "general", "slow-query"]
  
  vpc_security_group_ids = [aws_security_group.secure_db_sg.id]

  tags = {
    Name = "Secure Database"
  }
}

# KMS Key for RDS encryption
resource "aws_kms_key" "rds_key" {
  description             = "KMS key for RDS encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name = "RDS-Encryption-Key"
  }
}

# RDS Monitoring Role
resource "aws_iam_role" "rds_monitoring_role" {
  name = "rds-monitoring-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring_policy" {
  role       = aws_iam_role.rds_monitoring_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# Secure Database Security Group
resource "aws_security_group" "secure_db_sg" {
  name_prefix = "secure-db-sg"
  description = "Secure security group for database"

  # MySQL access only from web security group
  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.secure_web_sg.id]
    description     = "MySQL access from web servers only"
  }

  tags = {
    Name = "Secure Database Security Group"
  }
}

# CloudWatch Log Group with encryption and retention
resource "aws_cloudwatch_log_group" "app_logs" {
  name              = "/aws/ec2/secure-app"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.cloudwatch_key.arn

  tags = {
    Name = "Secure App Logs"
  }
}

# KMS Key for CloudWatch Logs
resource "aws_kms_key" "cloudwatch_key" {
  description             = "KMS key for CloudWatch Logs encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Effect = "Allow"
        Principal = {
          Service = "logs.us-west-2.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnEquals = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:us-west-2:${data.aws_caller_identity.current.account_id}:*"
          }
        }
      }
    ]
  })

  tags = {
    Name = "CloudWatch-Logs-Key"
  }
}
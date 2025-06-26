# =============================================================================
# S3 Bucket Misconfigurations Demo - Various Scenarios
# =============================================================================

# Scenario 1: Clearly misconfigured private bucket (SHOULD BE FIXED)
resource "aws_s3_bucket" "user_data" {
  bucket = "my-company-user-data-prod"
  acl    = "public-read"  # This is clearly wrong for user data!

  tags = {
    Environment = "production"
    DataType    = "sensitive"
    Owner       = "data-team"
  }
}

# Scenario 2: Intentional public bucket - CDN assets (SHOULD BE SECURED BUT REMAIN PUBLIC)
# Static assets for our company website
resource "aws_s3_bucket" "website_assets" {
  bucket = "mycompany-public-cdn-assets"
  acl    = "public-read"

  tags = {
    Environment = "production"
    Purpose     = "static-hosting"
    Website     = "company-site"
  }
}

# Scenario 3: Another intentional public bucket (SHOULD BE SECURED BUT REMAIN PUBLIC)
resource "aws_s3_bucket" "marketing_static" {
  bucket = "marketing-public-website"
  acl    = "public-read"

  tags = {
    Environment = "production"
    Team        = "marketing"
    Public      = "true"
    Purpose     = "web-hosting"
  }
}

# Scenario 4: Ambiguous case - needs human review (LIKELY TO BE FIXED)
resource "aws_s3_bucket" "app_backups" {
  bucket = "application-backup-store"
  acl    = "public-read"

  tags = {
    Environment = "staging"
    Purpose     = "backup"
  }
}

# Scenario 5: Database backups with wrong ACL (SHOULD BE FIXED)
resource "aws_s3_bucket" "db_backups" {
  bucket = "production-database-backups-2024"
  acl    = "public-read-write"  # Even worse - write access!
  
  tags = {
    Environment   = "production"
    DataType      = "database-backup"
    Compliance    = "required"
    Backup        = "automated"
  }
}

# Scenario 6: Frontend assets (SHOULD BE SECURED BUT REMAIN PUBLIC)
# For hosting our React application
resource "aws_s3_bucket" "frontend_app" {
  bucket = "myapp-frontend-ui-assets"
  acl    = "public-read"

  tags = {
    Environment = "production"
    Application = "web-frontend"
    Framework   = "react"
    Public      = "frontend"
  }
}

# Scenario 7: Log storage with wrong permissions (SHOULD BE FIXED)
resource "aws_s3_bucket" "application_logs" {
  bucket = "app-logs-central-storage"
  acl    = "public-read"

  tags = {
    Environment = "production"
    LogType     = "application"
    Retention   = "90days"
  }
}

# Scenario 8: Public documentation site (SHOULD BE SECURED BUT REMAIN PUBLIC)
# Company documentation and API docs
resource "aws_s3_bucket" "docs_site" {
  bucket = "company-public-docs-site"
  acl    = "public-read"

  tags = {
    Environment = "production"
    Purpose     = "documentation"
    Website     = "public"
    Content     = "docs"
  }
}

# Scenario 9: Analytics data with wrong ACL (SHOULD BE FIXED)
resource "aws_s3_bucket" "analytics_raw" {
  bucket = "customer-analytics-raw-data"
  acl    = "authenticated-read"  # Still too permissive

  tags = {
    Environment = "production"
    DataType    = "analytics"
    PII         = "contains"
    Team        = "data-science"
  }
}

# Scenario 10: Config files with public access (SHOULD BE FIXED)
resource "aws_s3_bucket" "app_configs" {
  bucket = "application-configuration-store"
  acl    = "public-read"

  tags = {
    Environment = "production"
    Purpose     = "configuration"
    Critical    = "true"
  }
}

# =============================================================================
# Additional AWS Resources (for context)
# =============================================================================

# IAM role for S3 access
resource "aws_iam_role" "s3_access_role" {
  name = "s3-bucket-access-role"

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

# Example of another resource type (not S3) - should be ignored by S3 fixer
resource "aws_security_group" "web_sg" {
  name_prefix = "web-security-group"
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # This is also a security issue, but different tool
  }
  
  tags = {
    Name = "web-security-group"
  }
}
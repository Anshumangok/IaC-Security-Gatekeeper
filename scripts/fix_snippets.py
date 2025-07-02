"""
Fix snippets for common IaC security issues
Each snippet is a template that can be formatted with resource-specific information
"""

FIX_SNIPPETS = {
    # AWS S3 Security Issues
    "CKV_AWS_21": """```hcl
# Add server-side encryption to S3 bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "{bucket_name}_encryption" {{
  bucket = aws_s3_bucket.{bucket_name}.id

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
    bucket_key_enabled = true
  }}
}}
```""",

    "CKV2_AWS_6": """```hcl
# Block public access to S3 bucket
resource "aws_s3_bucket_public_access_block" "{bucket_name}_pab" {{
  bucket = aws_s3_bucket.{bucket_name}.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}
```""",

    "CKV_AWS_20": """```hcl
# Remove public ACL and use private bucket
resource "aws_s3_bucket" "{bucket_name}" {{
  bucket = "your-bucket-name"
  # Remove: acl = "public-read"
}}

# Use bucket policy for controlled access instead
resource "aws_s3_bucket_policy" "{bucket_name}_policy" {{
  bucket = aws_s3_bucket.{bucket_name}.id
  
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Effect = "Allow"
        Principal = {{
          AWS = "arn:aws:iam::ACCOUNT-ID:user/USERNAME"
        }}
        Action = "s3:GetObject"
        Resource = "${{aws_s3_bucket.{bucket_name}.arn}}/*"
      }}
    ]
  }})
}}
```""",

    "CKV_AWS_18": """```hcl
# Enable S3 bucket access logging
resource "aws_s3_bucket_logging" "{bucket_name}_logging" {{
  bucket = aws_s3_bucket.{bucket_name}.id

  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "access-logs/"
}}

# Create separate bucket for access logs
resource "aws_s3_bucket" "log_bucket" {{
  bucket = "your-access-logs-bucket"
}}
```""",

    "CKV_AWS_19": """```hcl
# Enforce SSL-only access to S3 bucket
resource "aws_s3_bucket_policy" "{bucket_name}_ssl_policy" {{
  bucket = aws_s3_bucket.{bucket_name}.id

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Sid    = "DenyInsecureConnections"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          "${{aws_s3_bucket.{bucket_name}.arn}}",
          "${{aws_s3_bucket.{bucket_name}.arn}}/*"
        ]
        Condition = {{
          Bool = {{
            "aws:SecureTransport" = "false"
          }}
        }}
      }}
    ]
  }})
}}
```""",

    "CKV_AWS_144": """```hcl
# Enable S3 bucket cross-region replication
resource "aws_s3_bucket_replication_configuration" "{bucket_name}_replication" {{
  role   = aws_iam_role.replication.arn
  bucket = aws_s3_bucket.{bucket_name}.id

  rule {{
    id     = "replicate-to-backup-region"
    status = "Enabled"

    destination {{
      bucket        = aws_s3_bucket.backup.arn
      storage_class = "STANDARD_IA"
    }}
  }}

  depends_on = [aws_s3_bucket_versioning.{bucket_name}_versioning]
}}

# Enable versioning (required for replication)
resource "aws_s3_bucket_versioning" "{bucket_name}_versioning" {{
  bucket = aws_s3_bucket.{bucket_name}.id
  versioning_configuration {{
    status = "Enabled"
  }}
}}
```""",

    "CKV_AWS_145": """```hcl
# Set default encryption for S3 bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "{bucket_name}_encryption" {{
  bucket = aws_s3_bucket.{bucket_name}.id

  rule {{
    apply_server_side_encryption_by_default {{
      kms_master_key_id = aws_kms_key.{bucket_name}_key.arn
      sse_algorithm     = "aws:kms"
    }}
    bucket_key_enabled = true
  }}
}}

# Create KMS key for encryption
resource "aws_kms_key" "{bucket_name}_key" {{
  description             = "KMS key for {bucket_name} S3 bucket"
  deletion_window_in_days = 7
}}

resource "aws_kms_alias" "{bucket_name}_key_alias" {{
  name          = "alias/{bucket_name}-s3-key"
  target_key_id = aws_kms_key.{bucket_name}_key.key_id
}}
```""",

    # AWS IAM Security Issues
    "CKV_AWS_111": """```hcl
# Enable MFA for IAM users
resource "aws_iam_user_policy" "{bucket_name}_mfa_policy" {{
  name = "require-mfa"
  user = aws_iam_user.user.name

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Effect = "Deny"
        Action = "*"
        Resource = "*"
        Condition = {{
          BoolIfExists = {{
            "aws:MultiFactorAuthPresent" = "false"
          }}
        }}
      }}
    ]
  }})
}}
```""",

    "CKV_AWS_117": """```hcl
# Replace wildcard permissions with specific actions
# Instead of: Action = "*"
# Use specific actions like:
data "aws_iam_policy_document" "specific_permissions" {{
  statement {{
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject"
    ]
    resources = [
      "${{aws_s3_bucket.{bucket_name}.arn}}/*"
    ]
  }}
}}
```""",

    # AWS Security Group Issues
    "CKV_AWS_23": """```hcl
# Replace unrestricted ingress with specific CIDR blocks
resource "aws_security_group" "restricted_sg" {{
  name_prefix = "restricted-access"
  description = "Security group with restricted access"

  ingress {{
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Replace 0.0.0.0/0 with specific ranges
  }}

  egress {{
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }}
}}
```""",

    # AWS RDS Security Issues
    "CKV_AWS_16": """```hcl
# Enable RDS encryption
resource "aws_db_instance" "encrypted_db" {{
  # ... other configuration ...
  
  storage_encrypted = true
  kms_key_id       = aws_kms_key.rds_key.arn
}}

resource "aws_kms_key" "rds_key" {{
  description = "KMS key for RDS encryption"
}}
```""",

    # Generic fallback for unknown checks
    "UNKNOWN": """```hcl
# Manual remediation required
# Please refer to the Checkov documentation for specific guidance:
# https://www.checkov.io/5.Policy%20Index/terraform.html

# Common security practices:
# 1. Enable encryption at rest and in transit
# 2. Use least privilege access principles  
# 3. Enable logging and monitoring
# 4. Restrict public access
# 5. Use strong authentication (MFA)
```"""
}

# Severity mapping for checks (used as fallback)
SEVERITY_MAP = {
    # S3 Security
    "CKV_AWS_18": "MEDIUM",   # S3 access logging
    "CKV_AWS_19": "HIGH",     # S3 SSL-only policy
    "CKV_AWS_20": "HIGH",     # S3 public ACL
    "CKV_AWS_21": "HIGH",     # S3 encryption
    "CKV_AWS_144": "MEDIUM",  # S3 cross-region replication
    "CKV_AWS_145": "HIGH",    # S3 default encryption
    "CKV2_AWS_6": "HIGH",     # S3 public access block
    
    # IAM Security
    "CKV_AWS_111": "HIGH",    # IAM MFA
    "CKV_AWS_117": "HIGH",    # IAM wildcard permissions
    
    # Network Security
    "CKV_AWS_23": "HIGH",     # Security group unrestricted ingress
    
    # Database Security
    "CKV_AWS_16": "HIGH",     # RDS encryption
    
    # Secrets Management
    "CKV_AWS_79": "HIGH",     # Secrets in plain text
}

def get_fix_for_check(check_id, resource_name="resource"):
    """
    Get fix snippet for a specific check ID
    
    Args:
        check_id: The Checkov check ID (e.g., "CKV_AWS_21")
        resource_name: The name of the resource to use in the fix
    
    Returns:
        Formatted fix snippet as string
    """
    template = FIX_SNIPPETS.get(check_id, FIX_SNIPPETS["UNKNOWN"])
    
    try:
        return template.format(bucket_name=resource_name)
    except KeyError:
        # If template has different placeholders, return as-is
        return template

def get_severity_for_check(check_id):
    """
    Get severity level for a check ID
    
    Args:
        check_id: The Checkov check ID
        
    Returns:
        Severity level as string (HIGH, MEDIUM, LOW, etc.)
    """
    return SEVERITY_MAP.get(check_id, "MEDIUM")
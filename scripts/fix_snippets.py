FIX_SNIPPETS = {
    "CKV_AWS_21": """```hcl
resource \"aws_s3_bucket_server_side_encryption_configuration\" \"{bucket_name}_encryption\" {{
  bucket = aws_s3_bucket.{bucket_name}.id
  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = \"AES256\"
    }}
  }}
}}
```""",

    "CKV2_AWS_6": """```hcl
resource \"aws_s3_bucket_public_access_block\" \"{bucket_name}_pab\" {{
  bucket = aws_s3_bucket.{bucket_name}.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}
```"""
}
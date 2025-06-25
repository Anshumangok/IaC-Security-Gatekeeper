# scripts/fix_s3_encryption.py

import os
import re
import json
from datetime import datetime

def log_message(message, level="INFO"):
    """Log messages with timestamp and level"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")

def has_encryption_block(content):
    """Check if content already has encryption configuration"""
    patterns = [
        r'server_side_encryption_configuration',
        r'aws_s3_bucket_server_side_encryption_configuration',
        r'bucket_encryption'
    ]
    return any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns)

def extract_bucket_name(content):
    """Extract bucket resource name from Terraform content"""
    bucket_match = re.search(r'resource\s+"aws_s3_bucket"\s+"([^"]+)"', content)
    return bucket_match.group(1) if bucket_match else "example_bucket"

def inject_encryption_block(tf_path):
    """Inject encryption configuration for S3 buckets"""
    try:
        with open(tf_path, 'r') as f:
            content = f.read()
        
        # Check if file contains S3 bucket resources
        if 'resource "aws_s3_bucket"' not in content:
            log_message(f"No S3 bucket resources found in {tf_path}", "INFO")
            return False
            
        # Check if encryption is already configured
        if has_encryption_block(content):
            log_message(f"Encryption already configured in {tf_path}", "INFO")
            return False
            
        log_message(f"Adding encryption configuration to {tf_path}", "INFO")
        
        # Extract bucket resource name
        bucket_name = extract_bucket_name(content)
        
        # Find all S3 bucket resources and add encryption for each
        bucket_pattern = r'(resource\s+"aws_s3_bucket"\s+"([^"]+)"\s*{[^}]*})'
        matches = re.finditer(bucket_pattern, content, re.DOTALL)
        
        encryption_blocks = []
        for match in matches:
            resource_name = match.group(2)
            
            # Create encryption configuration block
            encryption_block = f'''
# Auto-generated encryption configuration for {resource_name}
resource "aws_s3_bucket_server_side_encryption_configuration" "{resource_name}_encryption" {{
  bucket = aws_s3_bucket.{resource_name}.id

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
    bucket_key_enabled = true
  }}
}}

# Public access block for {resource_name}
resource "aws_s3_bucket_public_access_block" "{resource_name}_pab" {{
  bucket = aws_s3_bucket.{resource_name}.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}
'''
            encryption_blocks.append(encryption_block)
        
        # Add all encryption blocks to the end of the file
        if encryption_blocks:
            content += '\n' + '\n'.join(encryption_blocks)
            
            # Write back to file
            with open(tf_path, 'w') as f:
                f.write(content)
            
            log_message(f"✅ Encryption blocks added to {tf_path}", "SUCCESS")
            return True
        else:
            log_message(f"No valid S3 bucket resources found in {tf_path}", "WARNING")
            return False
            
    except Exception as e:
        log_message(f"Error processing {tf_path}: {str(e)}", "ERROR")
        return False

def scan_and_fix():
    """Scan for Terraform files and fix S3 encryption issues"""
    log_message("Starting S3 encryption remediation scan", "INFO")
    
    fixed_files = []
    total_files = 0
    
    # Scan common Terraform directories
    search_paths = ["terraform", "tf", "infrastructure", ".", "modules"]
    
    for search_path in search_paths:
        if not os.path.exists(search_path):
            continue
            
        log_message(f"Scanning {search_path} for Terraform files", "INFO")
        
        for root, dirs, files in os.walk(search_path):
            # Skip hidden directories and common exclusions
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__']]
            
            for file in files:
                if file.endswith('.tf'):
                    total_files += 1
                    file_path = os.path.join(root, file)
                    
                    if inject_encryption_block(file_path):
                        fixed_files.append(file_path)
    
    # Generate summary report
    log_message("=" * 50, "INFO")
    log_message("S3 ENCRYPTION REMEDIATION SUMMARY", "INFO")
    log_message("=" * 50, "INFO")
    log_message(f"Total Terraform files scanned: {total_files}", "INFO")
    log_message(f"Files with encryption added: {len(fixed_files)}", "INFO")
    
    if fixed_files:
        log_message("Files modified:", "INFO")
        for file_path in fixed_files:
            log_message(f"  ✅ {file_path}", "SUCCESS")
    else:
        log_message("No files required encryption fixes", "INFO")
    
    # Create a fix report
    create_fix_report(fixed_files, total_files)
    
    return len(fixed_files) > 0

def create_fix_report(fixed_files, total_files):
    """Create a JSON report of the fixes applied"""
    report = {
        "timestamp": datetime.now().isoformat(),
        "fix_type": "s3_encryption",
        "total_files_scanned": total_files,
        "files_modified": len(fixed_files),
        "modified_files": fixed_files,
        "fixes_applied": [
            "Added aws_s3_bucket_server_side_encryption_configuration",
            "Added aws_s3_bucket_public_access_block",
            "Enabled AES256 encryption",
            "Enabled bucket key for cost optimization"
        ]
    }
    
    os.makedirs("checkov_reports", exist_ok=True)
    with open("checkov_reports/s3_fixes_applied.json", "w") as f:
        json.dump(report, f, indent=2)
    
    log_message("Fix report saved to checkov_reports/s3_fixes_applied.json", "INFO")

if __name__ == "__main__":
    try:
        fixes_applied = scan_and_fix()
        exit_code = 0 if fixes_applied else 0  # Always exit 0 for CI/CD
        log_message(f"S3 encryption remediation completed with exit code {exit_code}", "INFO")
        exit(exit_code)
    except Exception as e:
        log_message(f"Fatal error in S3 encryption remediation: {str(e)}", "ERROR")
        exit(1)
# scripts/fix_s3_encryption.py

import os
import re
import json
from datetime import datetime
from typing import List, Tuple, Dict

def log_message(message: str, level: str = "INFO"):
    """Log messages with timestamp and level"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")

def has_encryption_block(content: str) -> bool:
    """Check if content already has encryption configuration"""
    patterns = [
        r'server_side_encryption_configuration',
        r'aws_s3_bucket_server_side_encryption_configuration',
        r'bucket_encryption',
        r'sse_algorithm',
        r'apply_server_side_encryption_by_default'
    ]
    return any(re.search(pattern, content, re.IGNORECASE | re.MULTILINE) for pattern in patterns)

def extract_bucket_resources(content: str) -> List[Tuple[str, str]]:
    """Extract all S3 bucket resource names and their full definitions"""
    bucket_pattern = r'resource\s+"aws_s3_bucket"\s+"([^"]+)"\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}'
    matches = re.finditer(bucket_pattern, content, re.DOTALL | re.MULTILINE)
    
    buckets = []
    for match in matches:
        resource_name = match.group(1)
        resource_definition = match.group(2)
        buckets.append((resource_name, resource_definition))
    
    return buckets

def has_public_access_block(content: str) -> bool:
    """Check if content already has public access block configuration"""
    patterns = [
        r'aws_s3_bucket_public_access_block',
        r'block_public_acls',
        r'restrict_public_buckets'
    ]
    return any(re.search(pattern, content, re.IGNORECASE | re.MULTILINE) for pattern in patterns)

def inject_encryption_block(tf_path: str) -> bool:
    """Inject encryption configuration for S3 buckets"""
    try:
        with open(tf_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check if file contains S3 bucket resources
        if 'resource "aws_s3_bucket"' not in content:
            log_message(f"No S3 bucket resources found in {tf_path}", "INFO")
            return False
            
        # Check if encryption is already configured
        if has_encryption_block(content):
            log_message(f"Encryption already configured in {tf_path}", "INFO")
            return False
        
        log_message(f"Processing S3 buckets in {tf_path}", "INFO")
        
        # Extract all bucket resources
        bucket_resources = extract_bucket_resources(content)
        
        if not bucket_resources:
            log_message(f"No valid S3 bucket resources found in {tf_path}", "WARNING")
            return False
        
        encryption_blocks = []
        public_access_blocks = []
        
        # Generate encryption and public access blocks for each bucket
        for resource_name, resource_def in bucket_resources:
            log_message(f"Adding encryption for bucket resource: {resource_name}", "INFO")
            
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
}}'''
            encryption_blocks.append(encryption_block)
            
            # Add public access block only if not already present
            if not has_public_access_block(content):
                public_access_block = f'''
# Auto-generated public access block for {resource_name}
resource "aws_s3_bucket_public_access_block" "{resource_name}_pab" {{
  bucket = aws_s3_bucket.{resource_name}.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}'''
                public_access_blocks.append(public_access_block)
        
        # Add all blocks to the end of the file
        all_blocks = encryption_blocks + public_access_blocks
        if all_blocks:
            # Ensure proper spacing
            content = content.rstrip() + '\n'
            content += '\n'.join(all_blocks) + '\n'
            
            # Write back to file
            with open(tf_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            log_message(f"✅ Added {len(encryption_blocks)} encryption blocks and {len(public_access_blocks)} public access blocks to {tf_path}", "SUCCESS")
            return True
        else:
            log_message(f"No blocks to add for {tf_path}", "INFO")
            return False
            
    except UnicodeDecodeError:
        log_message(f"Error reading {tf_path}: File encoding issue", "ERROR")
        return False
    except Exception as e:
        log_message(f"Error processing {tf_path}: {str(e)}", "ERROR")
        return False

def is_terraform_file(file_path: str) -> bool:
    """Check if a file is a Terraform file with S3 content"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read(1000)  # Read first 1000 chars for quick check
            return 'aws_s3_bucket' in content and 'resource' in content
    except:
        return False

def scan_and_fix() -> bool:
    """Scan for Terraform files and fix S3 encryption issues"""
    log_message("Starting S3 encryption remediation scan", "INFO")
    
    fixed_files = []
    total_files = 0
    skipped_files = 0
    
    # Scan common Terraform directories and current directory
    search_paths = [".", "terraform", "tf", "infrastructure", "modules", "environments"]
    
    for search_path in search_paths:
        if not os.path.exists(search_path):
            continue
            
        log_message(f"Scanning {search_path} for Terraform files", "INFO")
        
        for root, dirs, files in os.walk(search_path):
            # Skip hidden directories, common exclusions, and terraform state directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in [
                'node_modules', '__pycache__', '.terraform', '.git'
            ]]
            
            for file in files:
                if file.endswith('.tf'):
                    total_files += 1
                    file_path = os.path.join(root, file)
                    
                    # Quick check if this file has S3 resources
                    if is_terraform_file(file_path):
                        log_message(f"Processing: {file_path}", "INFO")
                        
                        if inject_encryption_block(file_path):
                            fixed_files.append(file_path)
                    else:
                        skipped_files += 1
                        log_message(f"Skipped: {file_path} (no S3 resources)", "DEBUG")
    
    # Generate summary report
    log_message("=" * 60, "INFO")
    log_message("S3 ENCRYPTION REMEDIATION SUMMARY", "INFO")
    log_message("=" * 60, "INFO")
    log_message(f"Total Terraform files scanned: {total_files}", "INFO")
    log_message(f"Files with S3 buckets: {total_files - skipped_files}", "INFO")
    log_message(f"Files with encryption added: {len(fixed_files)}", "INFO")
    log_message(f"Files skipped (no S3): {skipped_files}", "INFO")
    
    if fixed_files:
        log_message("Files modified:", "SUCCESS")
        for file_path in fixed_files:
            log_message(f"  ✅ {file_path}", "SUCCESS")
    else:
        log_message("ℹ️ No files required encryption fixes", "INFO")
    
    # Create a fix report
    create_fix_report(fixed_files, total_files, total_files - skipped_files)
    
    return len(fixed_files) > 0

def create_fix_report(fixed_files: List[str], total_files: int, s3_files: int):
    """Create a JSON report of the fixes applied"""
    report = {
        "timestamp": datetime.now().isoformat(),
        "fix_type": "s3_encryption",
        "scan_summary": {
            "total_terraform_files": total_files,
            "files_with_s3_buckets": s3_files,
            "files_modified": len(fixed_files)
        },
        "modified_files": fixed_files,
        "fixes_applied": {
            "encryption_configurations": f"Added aws_s3_bucket_server_side_encryption_configuration resources",
            "public_access_blocks": f"Added aws_s3_bucket_public_access_block resources",
            "encryption_algorithm": "AES256",
            "bucket_key_enabled": True,
            "public_access_restrictions": {
                "block_public_acls": True,
                "block_public_policy": True,
                "ignore_public_acls": True,
                "restrict_public_buckets": True
            }
        },
        "compliance_improvements": [
            "CKV_AWS_141: Ensure that S3 bucket has encryption",
            "CKV_AWS_144: Ensure that S3 bucket has public access blocked",
            "CKV_AWS_145: Ensure that S3 bucket has public read access blocked",
            "CKV_AWS_146: Ensure that S3 bucket has public write access blocked"
        ]
    }
    
    os.makedirs("checkov_reports", exist_ok=True)
    report_path = "checkov_reports/s3_fixes_applied.json"
    
    with open(report_path, "w", encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    
    log_message(f"Fix report saved to {report_path}", "INFO")

if __name__ == "__main__":
    try:
        log_message("🔐 Starting S3 encryption auto-remediation", "INFO")
        fixes_applied = scan_and_fix()
        
        if fixes_applied:
            log_message("🎉 S3 encryption remediation completed successfully", "SUCCESS")
            exit_code = 0
        else:
            log_message("ℹ️ S3 encryption remediation completed - no changes needed", "INFO")
            exit_code = 0
        
        log_message(f"Process completed with exit code {exit_code}", "INFO")
        exit(exit_code)
        
    except Exception as e:
        log_message(f"💥 Fatal error in S3 encryption remediation: {str(e)}", "ERROR")
        exit(1)
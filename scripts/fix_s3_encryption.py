#!/usr/bin/env python3
"""
S3 Security Fix Script
=====================

Enhanced script to automatically fix S3 security misconfigurations in Terraform files.
This script addresses multiple S3 security issues including encryption, public access, and logging.

Usage:
    python fix_s3_security.py [options]

Options:
    --source-dir: Directory containing Terraform files (default: terraform)
    --output-dir: Directory to save fixed files (default: fixed_terraform)
    --dry-run: Show what would be fixed without making changes
    --verbose: Enable verbose output
    --backup: Create backup of original files
"""

import os
import re
import json
import argparse
import shutil
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Set, Tuple, Optional


class S3SecurityFixer:
    """Main class for fixing S3 security issues in Terraform files."""
    
    def __init__(self, source_dir: str = "terraform", output_dir: str = "fixed_terraform", 
                 dry_run: bool = False, verbose: bool = False, backup: bool = False):
        self.source_dir = Path(source_dir)
        self.output_dir = Path(output_dir)
        self.dry_run = dry_run
        self.verbose = verbose
        self.backup = backup
        
        # Ensure output directory exists
        if not self.dry_run:
            self.output_dir.mkdir(exist_ok=True)
        
        # Security issue tracking
        self.issues_found = []
        self.fixes_applied = []
        self.files_processed = 0
        self.files_fixed = 0
    
    def log(self, message: str, level: str = "INFO"):
        """Log messages with timestamps."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "INFO": "ℹ️",
            "WARN": "⚠️", 
            "ERROR": "❌",
            "SUCCESS": "✅",
            "FIX": "🔧"
        }.get(level, "📝")
        
        print(f"[{timestamp}] {prefix} {message}")
    
    def verbose_log(self, message: str, level: str = "INFO"):
        """Log verbose messages only if verbose mode is enabled."""
        if self.verbose:
            self.log(message, level)
    
    def find_terraform_files(self) -> List[Path]:
        """Find all Terraform files in the source directory."""
        tf_files = []
        
        if not self.source_dir.exists():
            self.log(f"Source directory not found: {self.source_dir}", "ERROR")
            return tf_files
        
        for root, _, files in os.walk(self.source_dir):
            for file in files:
                if file.endswith('.tf'):
                    tf_files.append(Path(root) / file)
        
        self.log(f"Found {len(tf_files)} Terraform files")
        return tf_files
    
    def extract_bucket_resources(self, content: str) -> List[Dict[str, str]]:
        """Extract S3 bucket resource information from Terraform content."""
        bucket_pattern = r'resource\s+"aws_s3_bucket"\s+"(\w+)"\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
        matches = re.findall(bucket_pattern, content, re.DOTALL)
        
        buckets = []
        for match in matches:
            bucket_name = match[0]
            bucket_config = match[1]
            buckets.append({
                'name': bucket_name,
                'config': bucket_config,
                'full_match': match
            })
        
        return buckets
    
    def has_encryption_configuration(self, content: str, bucket_name: str) -> bool:
        """Check if bucket already has encryption configuration."""
        patterns = [
            f'aws_s3_bucket_server_side_encryption_configuration.*{bucket_name}',
            f'{bucket_name}.*server_side_encryption_configuration',
            f'resource.*server_side_encryption_configuration.*{bucket_name}',
            f'{bucket_name}_encryption'
        ]
        
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                return True
        return False
    
    def has_public_access_block(self, content: str, bucket_name: str) -> bool:
        """Check if bucket already has public access block."""
        patterns = [
            f'aws_s3_bucket_public_access_block.*{bucket_name}',
            f'{bucket_name}.*public_access_block',
            f'{bucket_name}_pab'
        ]
        
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                return True
        return False
    
    def has_logging_configuration(self, content: str, bucket_name: str) -> bool:
        """Check if bucket already has logging configuration."""
        patterns = [
            f'aws_s3_bucket_logging.*{bucket_name}',
            f'{bucket_name}.*logging',
            f'{bucket_name}_logging'
        ]
        
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                return True
        return False
    
    def has_versioning_configuration(self, content: str, bucket_name: str) -> bool:
        """Check if bucket already has versioning configuration."""
        patterns = [
            f'aws_s3_bucket_versioning.*{bucket_name}',
            f'{bucket_name}.*versioning',
            f'{bucket_name}_versioning'
        ]
        
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                return True
        return False
    
    def check_public_acl(self, content: str) -> bool:
        """Check if there are public ACLs configured."""
        public_acl_patterns = [
            r'acl\s*=\s*"public-read"',
            r'acl\s*=\s*"public-read-write"',
            r"acl\s*=\s*'public-read'",
            r"acl\s*=\s*'public-read-write'"
        ]
        
        for pattern in public_acl_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False
    
    def generate_encryption_config(self, bucket_name: str, encryption_type: str = "AES256") -> str:
        """Generate S3 encryption configuration."""
        if encryption_type.upper() == "KMS":
            return f'''
# S3 KMS Encryption - Added by S3 Security Fixer
resource "aws_s3_bucket_server_side_encryption_configuration" "{bucket_name}_encryption" {{
  bucket = aws_s3_bucket.{bucket_name}.id

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "alias/aws/s3"
    }}
    bucket_key_enabled = true
  }}
}}'''
        else:
            return f'''
# S3 AES256 Encryption - Added by S3 Security Fixer
resource "aws_s3_bucket_server_side_encryption_configuration" "{bucket_name}_encryption" {{
  bucket = aws_s3_bucket.{bucket_name}.id

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
    bucket_key_enabled = true
  }}
}}'''
    
    def generate_public_access_block(self, bucket_name: str) -> str:
        """Generate S3 public access block configuration."""
        return f'''
# S3 Public Access Block - Added by S3 Security Fixer
resource "aws_s3_bucket_public_access_block" "{bucket_name}_pab" {{
  bucket = aws_s3_bucket.{bucket_name}.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}'''
    
    def generate_logging_config(self, bucket_name: str, log_bucket: Optional[str] = None) -> str:
        """Generate S3 access logging configuration."""
        target_bucket = log_bucket or f"aws_s3_bucket.{bucket_name}.id"
        return f'''
# S3 Access Logging - Added by S3 Security Fixer
resource "aws_s3_bucket_logging" "{bucket_name}_logging" {{
  bucket = aws_s3_bucket.{bucket_name}.id

  target_bucket = {target_bucket}
  target_prefix = "access-logs/{bucket_name}/"
}}'''
    
    def generate_versioning_config(self, bucket_name: str) -> str:
        """Generate S3 versioning configuration."""
        return f'''
# S3 Versioning - Added by S3 Security Fixer
resource "aws_s3_bucket_versioning" "{bucket_name}_versioning" {{
  bucket = aws_s3_bucket.{bucket_name}.id
  
  versioning_configuration {{
    status = "Enabled"
  }}
}}'''
    
    def fix_public_acls(self, content: str) -> str:
        """Fix public ACL configurations."""
        replacements = [
            (r'acl\s*=\s*"public-read"', 'acl = "private"'),
            (r'acl\s*=\s*"public-read-write"', 'acl = "private"'),
            (r"acl\s*=\s*'public-read'", "acl = 'private'"),
            (r"acl\s*=\s*'public-read-write'", "acl = 'private'")
        ]
        
        modified = content
        for pattern, replacement in replacements:
            if re.search(pattern, modified, re.IGNORECASE):
                modified = re.sub(pattern, replacement, modified, flags=re.IGNORECASE)
                self.verbose_log(f"Fixed public ACL: {pattern} -> {replacement}")
        
        return modified
    
    def analyze_s3_security(self, content: str, file_path: Path) -> Dict[str, List[str]]:
        """Analyze S3 security issues in the given content."""
        issues = {
            'missing_encryption': [],
            'missing_public_access_block': [],
            'public_acls': [],
            'missing_logging': [],
            'missing_versioning': []
        }
        
        buckets = self.extract_bucket_resources(content)
        
        for bucket in buckets:
            bucket_name = bucket['name']
            
            # Check for missing encryption
            if not self.has_encryption_configuration(content, bucket_name):
                issues['missing_encryption'].append(bucket_name)
            
            # Check for missing public access block
            if not self.has_public_access_block(content, bucket_name):
                issues['missing_public_access_block'].append(bucket_name)
            
            # Check for missing logging
            if not self.has_logging_configuration(content, bucket_name):
                issues['missing_logging'].append(bucket_name)
            
            # Check for missing versioning
            if not self.has_versioning_configuration(content, bucket_name):
                issues['missing_versioning'].append(bucket_name)
        
        # Check for public ACLs
        if self.check_public_acl(content):
            issues['public_acls'].append(str(file_path))
        
        return issues
    
    def apply_security_fixes(self, content: str, file_path: Path) -> Tuple[str, List[str]]:
        """Apply security fixes to the content."""
        fixed_content = content
        fixes_applied = []
        
        # Analyze issues first
        issues = self.analyze_s3_security(content, file_path)
        buckets = self.extract_bucket_resources(content)
        
        # Fix public ACLs first
        if issues['public_acls']:
            fixed_content = self.fix_public_acls(fixed_content)
            fixes_applied.append("Fixed public ACLs")
        
        # Apply fixes for each bucket
        for bucket in buckets:
            bucket_name = bucket['name']
            
            # Add encryption if missing
            if bucket_name in issues['missing_encryption']:
                encryption_config = self.generate_encryption_config(bucket_name)
                fixed_content += encryption_config
                fixes_applied.append(f"Added encryption for {bucket_name}")
            
            # Add public access block if missing
            if bucket_name in issues['missing_public_access_block']:
                pab_config = self.generate_public_access_block(bucket_name)
                fixed_content += pab_config
                fixes_applied.append(f"Added public access block for {bucket_name}")
            
            # Add logging if missing (optional - can be commented out if not needed)
            # if bucket_name in issues['missing_logging']:
            #     logging_config = self.generate_logging_config(bucket_name)
            #     fixed_content += logging_config
            #     fixes_applied.append(f"Added logging for {bucket_name}")
            
            # Add versioning if missing (optional - can be commented out if not needed)
            # if bucket_name in issues['missing_versioning']:
            #     versioning_config = self.generate_versioning_config(bucket_name)
            #     fixed_content += versioning_config
            #     fixes_applied.append(f"Added versioning for {bucket_name}")
        
        return fixed_content, fixes_applied
    
    def process_file(self, file_path: Path) -> bool:
        """Process a single Terraform file."""
        self.verbose_log(f"Processing file: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                original_content = f.read()
            
            # Skip files without S3 bucket resources
            if 'aws_s3_bucket' not in original_content:
                self.verbose_log(f"No S3 buckets found in {file_path}")
                return False
            
            self.files_processed += 1
            
            # Analyze security issues
            issues = self.analyze_s3_security(original_content, file_path)
            total_issues = sum(len(issue_list) for issue_list in issues.values())
            
            if total_issues == 0:
                self.verbose_log(f"No security issues found in {file_path}")
                return False
            
            self.log(f"Found {total_issues} security issues in {file_path.name}", "WARN")
            
            # Apply fixes
            fixed_content, fixes_applied = self.apply_security_fixes(original_content, file_path)
            
            if not fixes_applied:
                self.verbose_log(f"No fixes applied to {file_path}")
                return False
            
            # Save fixed content
            if not self.dry_run:
                # Create backup if requested
                if self.backup:
                    backup_path = file_path.with_suffix('.tf.backup')
                    shutil.copy2(file_path, backup_path)
                    self.verbose_log(f"Created backup: {backup_path}")
                
                # Save fixed file
                output_file = self.output_dir / file_path.name
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(fixed_content)
                
                self.log(f"Fixed file saved: {output_file}", "SUCCESS")
            else:
                self.log(f"DRY RUN: Would fix {len(fixes_applied)} issues in {file_path.name}")
            
            # Track fixes
            self.fixes_applied.extend(fixes_applied)
            self.files_fixed += 1
            
            # Log applied fixes
            for fix in fixes_applied:
                self.log(fix, "FIX")
            
            return True
            
        except Exception as e:
            self.log(f"Error processing {file_path}: {e}", "ERROR")
            return False
    
    def generate_summary_report(self) -> str:
        """Generate a comprehensive summary report."""
        report = f"""# S3 Security Fix Summary Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Mode:** {'DRY RUN' if self.dry_run else 'FIX APPLIED'}

## Summary Statistics

- **Files Processed:** {self.files_processed}
- **Files Fixed:** {self.files_fixed}
- **Total Fixes Applied:** {len(self.fixes_applied)}

## Applied Fixes

"""
        
        if self.fixes_applied:
            for i, fix in enumerate(self.fixes_applied, 1):
                report += f"{i}. {fix}\n"
        else:
            report += "No fixes were applied.\n"
        
        report += f"""

## Security Improvements

The following security configurations have been {'planned' if self.dry_run else 'applied'}:

### ✅ Server-Side Encryption
- AES256 encryption enabled for buckets without encryption
- Bucket key enabled for cost optimization

### ✅ Public Access Protection
- Public access blocks configured to prevent accidental public exposure
- Public ACLs converted to private ACLs

### ✅ Additional Security (Optional)
- Access logging configuration (commented out by default)
- Versioning configuration (commented out by default)

## Next Steps

1. **Review Changes:** Examine all generated files before applying
2. **Test Configuration:** Validate in development environment first
3. **Plan Application:** Use terraform plan to review changes
4. **Apply Safely:** Deploy
#!/usr/bin/env python3
"""
S3 Security Remediation Script
Automatically fixes S3 bucket security misconfigurations in Terraform files.
"""

import os
import json
import re
import shutil
from pathlib import Path
from datetime import datetime
import argparse

class S3SecurityRemediator:
    def __init__(self, source_dir="terraform", dry_run=True):
        self.source_dir = Path(source_dir)
        self.dry_run = dry_run
        self.fix_artifacts_dir = Path("fix_artifacts")
        self.fixes_applied = []
        self.issues_found = []
        
        # Ensure fix artifacts directory exists
        self.fix_artifacts_dir.mkdir(exist_ok=True)
        
    def scan_terraform_files(self):
        """Scan for Terraform files with S3 bucket configurations."""
        tf_files = []
        for file_path in self.source_dir.rglob("*.tf"):
            if file_path.is_file():
                tf_files.append(file_path)
        return tf_files
    
    def read_file_content(self, file_path):
        """Read and return file content."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return None
    
    def find_s3_buckets(self, content):
        """Find S3 bucket resources in Terraform content."""
        # Pattern to match aws_s3_bucket resources
        bucket_pattern = r'resource\s+"aws_s3_bucket"\s+"([^"]+)"\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
        buckets = []
        
        for match in re.finditer(bucket_pattern, content, re.DOTALL):
            bucket_name = match.group(1)
            bucket_config = match.group(2)
            start_pos = match.start()
            end_pos = match.end()
            
            buckets.append({
                'name': bucket_name,
                'config': bucket_config,
                'full_match': match.group(0),
                'start': start_pos,
                'end': end_pos
            })
        
        return buckets
    
    def check_bucket_security_issues(self, bucket_config):
        """Check for security issues in bucket configuration."""
        issues = []
        
        # Check for public ACLs (CKV_AWS_20)
        if re.search(r'acl\s*=\s*["\']public-read["\']', bucket_config):
            issues.append('public_read_acl')
        if re.search(r'acl\s*=\s*["\']public-read-write["\']', bucket_config):
            issues.append('public_read_write_acl')
        
        # Check for missing server-side encryption (CKV_AWS_21)
        if not re.search(r'server_side_encryption_configuration', bucket_config):
            issues.append('missing_encryption')
        
        # Check for missing public access block (CKV2_AWS_6)
        if not re.search(r'aws_s3_bucket_public_access_block', bucket_config):
            issues.append('missing_public_access_block')
        
        return issues
    
    def generate_secure_bucket_config(self, bucket_name, original_config, issues):
        """Generate a secure version of the S3 bucket configuration."""
        secure_config = original_config
        
        # Fix public ACLs
        if 'public_read_acl' in issues or 'public_read_write_acl' in issues:
            secure_config = re.sub(r'acl\s*=\s*["\']public-read(-write)?["\']', 'acl = "private"', secure_config)
        
        # Add server-side encryption if missing
        if 'missing_encryption' in issues:
            encryption_block = '''
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
      bucket_key_enabled = true
    }
  }'''
            secure_config += encryption_block
        
        # Add versioning for better security
        if not re.search(r'versioning', secure_config):
            versioning_block = '''
  versioning {
    enabled = true
  }'''
            secure_config += versioning_block
        
        # Add security tags
        if not re.search(r'tags\s*=', secure_config):
            tags_block = '''
  tags = {
    Environment = "production"
    Security = "enhanced"
    ManagedBy = "security-gatekeeper"
  }'''
            secure_config += tags_block
        
        # Generate the complete resource block
        full_config = f'''resource "aws_s3_bucket" "{bucket_name}" {{{secure_config}
}}'''
        
        # Add public access block resource if missing
        if 'missing_public_access_block' in issues:
            public_access_block = f'''
resource "aws_s3_bucket_public_access_block" "{bucket_name}_pab" {{
  bucket = aws_s3_bucket.{bucket_name}.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  depends_on = [aws_s3_bucket.{bucket_name}]
}}'''
            full_config += public_access_block
        
        return full_config
    
    def process_file(self, file_path):
        """Process a single Terraform file for S3 security issues."""
        print(f"Processing: {file_path}")
        content = self.read_file_content(file_path)
        if not content:
            return
        
        buckets = self.find_s3_buckets(content)
        if not buckets:
            print(f"  No S3 buckets found in {file_path}")
            return
        
        file_issues = []
        fixed_content = content
        
        for bucket in buckets:
            bucket_name = bucket['name']
            bucket_config = bucket['config']
            issues = self.check_bucket_security_issues(bucket_config)
            
            if issues:
                print(f"  Found issues in bucket '{bucket_name}': {', '.join(issues)}")
                
                # Check if this is an intentionally public bucket
                if self.is_intentionally_public(bucket_name, bucket_config):
                    print(f"    Bucket '{bucket_name}' appears to be intentionally public, applying enhanced security only")
                    secure_config = self.generate_enhanced_public_bucket_config(bucket_name, bucket_config)
                else:
                    secure_config = self.generate_secure_bucket_config(bucket_name, bucket_config, issues)
                
                file_issues.append({
                    'bucket_name': bucket_name,
                    'issues': issues,
                    'original_config': bucket['full_match'],
                    'fixed_config': secure_config
                })
                
                # Replace in content for the fixed file
                fixed_content = fixed_content.replace(bucket['full_match'], secure_config)
        
        if file_issues:
            self.issues_found.extend(file_issues)
            
            # Save the fixed file
            if not self.dry_run:
                fixed_file_path = self.fix_artifacts_dir / f"fixed_{file_path.name}"
                with open(fixed_file_path, 'w', encoding='utf-8') as f:
                    f.write(fixed_content)
                print(f"  Created fixed file: {fixed_file_path}")
            else:
                # In dry-run mode, still create the fixed file for review
                fixed_file_path = self.fix_artifacts_dir / f"preview_{file_path.name}"
                with open(fixed_file_path, 'w', encoding='utf-8') as f:
                    f.write(fixed_content)
                print(f"  Created preview file: {fixed_file_path}")
            
            self.fixes_applied.extend(file_issues)
    
    def is_intentionally_public(self, bucket_name, config):
        """Determine if a bucket is intentionally public based on naming and tags."""
        public_indicators = [
            'public', 'website', 'cdn', 'static', 'assets', 'media'
        ]
        
        # Check bucket name
        if any(indicator in bucket_name.lower() for indicator in public_indicators):
            return True
        
        # Check for specific tags indicating intentional public access
        if re.search(r'public.*=.*["\']true["\']', config, re.IGNORECASE):
            return True
        
        return False
    
    def generate_enhanced_public_bucket_config(self, bucket_name, original_config):
        """Generate enhanced security config for intentionally public buckets."""
        secure_config = original_config
        
        # Keep public ACL but add other security measures
        # Add server-side encryption
        if not re.search(r'server_side_encryption_configuration', secure_config):
            encryption_block = '''
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
      bucket_key_enabled = true
    }
  }'''
            secure_config += encryption_block
        
        # Add versioning
        if not re.search(r'versioning', secure_config):
            versioning_block = '''
  versioning {
    enabled = true
  }'''
            secure_config += versioning_block
        
        # Add security tags
        if not re.search(r'tags\s*=', secure_config):
            tags_block = '''
  tags = {
    Environment = "production"
    Security = "enhanced-public"
    PublicAccess = "intentional"
    ManagedBy = "security-gatekeeper"
  }'''
            secure_config += tags_block
        
        return f'''resource "aws_s3_bucket" "{bucket_name}" {{{secure_config}
}}'''
    
    def generate_remediation_report(self):
        """Generate a detailed remediation report."""
        report = f"""# S3 Security Remediation Report

Generated: {datetime.now().isoformat()}
Mode: {'DRY RUN' if self.dry_run else 'LIVE'}

## Summary
- Files processed: {len(self.fixes_applied)}
- Security issues found: {len(self.issues_found)}
- Fixes applied: {len(self.fixes_applied)}

## Issues Found and Fixed

"""
        
        for issue in self.issues_found:
            report += f"""### Bucket: `{issue['bucket_name']}`
**Issues:** {', '.join(issue['issues'])}

**Original Configuration:**
```hcl
{issue['original_config'][:200]}...
```

**Fixed Configuration:**
```hcl
{issue['fixed_config'][:200]}...
```

---

"""
        
        report += f"""
## Security Improvements Applied

1. **Private ACLs**: Changed public bucket ACLs to private where appropriate
2. **Encryption**: Added AES256 server-side encryption to all buckets
3. **Versioning**: Enabled versioning for data protection
4. **Public Access Blocks**: Added comprehensive public access restrictions
5. **Security Tags**: Applied security and management tags

## Next Steps

1. Review the generated configurations in the fix_artifacts directory
2. Test the configurations in a development environment
3. Apply the changes during a maintenance window
4. Monitor for any access issues after deployment

## Files Generated

"""
        
        for file_path in self.fix_artifacts_dir.glob("*.tf"):
            report += f"- `{file_path.name}`\n"
        
        return report
    
    def run(self):
        """Run the complete remediation process."""
        print(f"🔍 Starting S3 Security Remediation")
        print(f"Source directory: {self.source_dir}")
        print(f"Mode: {'DRY RUN' if self.dry_run else 'LIVE'}")
        print("-" * 50)
        
        # Find and process all Terraform files
        tf_files = self.scan_terraform_files()
        print(f"Found {len(tf_files)} Terraform files")
        
        for tf_file in tf_files:
            self.process_file(tf_file)
        
        # Generate summary report
        report = self.generate_remediation_report()
        report_path = self.fix_artifacts_dir / "s3_remediation_report.md"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report)
        
        # Generate JSON summary for automation
        summary = {
            'timestamp': datetime.now().isoformat(),
            'dry_run': self.dry_run,
            'files_processed': len(tf_files),
            'issues_found': len(self.issues_found),
            'fixes_applied': len(self.fixes_applied),
            'issues_detail': self.issues_found
        }
        
        summary_path = self.fix_artifacts_dir / "remediation_summary.json"
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)
        
        print("-" * 50)
        print(f"✅ Remediation complete!")
        print(f"📊 Report saved to: {report_path}")
        print(f"📋 Summary saved to: {summary_path}")
        
        if self.fixes_applied:
            print(f"🔧 {len(self.fixes_applied)} fixes generated")
            if self.dry_run:
                print("🔍 Running in DRY RUN mode - review files before applying")
        else:
            print("✨ No S3 security issues found!")


def main():
    parser = argparse.ArgumentParser(description='S3 Security Remediation Tool')
    parser.add_argument('--source-dir', default='terraform', help='Directory to scan for Terraform files')
    parser.add_argument('--dry-run', action='store_true', default=True, help='Run in dry-run mode')
    parser.add_argument('--live', action='store_true', help='Run in live mode (applies fixes)')
    
    args = parser.parse_args()
    
    # Handle environment variables (for GitHub Actions)
    source_dir = os.getenv('SOURCE_DIR', args.source_dir)
    dry_run = os.getenv('DRY_RUN', 'true').lower() == 'true'
    
    if args.live:
        dry_run = False
    
    # Initialize and run remediation
    remediator = S3SecurityRemediator(source_dir=source_dir, dry_run=dry_run)
    remediator.run()


if __name__ == "__main__":
    main()
#!/usr/bin/env python3

"""
S3 Security Remediation Script
Automatically fixes S3 bucket security misconfigurations in Terraform files.
"""

import os
import re
import argparse
from pathlib import Path
from datetime import datetime

class S3SecurityRemediator:
    def __init__(self, source_dir="terraform", dry_run=True):
        self.source_dir = Path(source_dir)
        self.dry_run = dry_run
        self.fix_artifacts_dir = Path("fix_artifacts")
        self.fixes_applied = []
        self.issues_found = []
        self.fix_artifacts_dir.mkdir(exist_ok=True)

    def scan_terraform_files(self):
        return [f for f in self.source_dir.rglob("*.tf") if f.is_file()]

    def read_file_content(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return None

    def find_s3_buckets(self, content):
        bucket_pattern = r'resource\s+"aws_s3_bucket"\s+"([^"]+)"\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
        buckets = []
        for match in re.finditer(bucket_pattern, content, re.DOTALL):
            buckets.append({
                'name': match.group(1),
                'config': match.group(2),
                'full_match': match.group(0),
                'start': match.start(),
                'end': match.end()
            })
        return buckets

    def check_bucket_security_issues(self, config):
        issues = []
        if re.search(r'acl\s*=\s*["\']public-read(-write)?["\']', config):
            issues.append("public_acl")
        if "server_side_encryption_configuration" not in config:
            issues.append("missing_encryption")
        if "aws_s3_bucket_public_access_block" not in config:
            issues.append("missing_public_access_block")
        return issues

    def is_intentionally_public(self, bucket_name, config):
        keywords = ['public', 'cdn', 'website', 'static']
        tags_public = re.search(r'tags\s*=\s*{[^}]*public[^}]*=[^}]*["\']true["\']', config, re.IGNORECASE)
        name_signal = any(k in bucket_name.lower() for k in keywords)
        return name_signal or tags_public

    def generate_fixed_bucket(self, bucket_name, config, issues, intentional=False):
        result = config
        if not intentional:
            if "public_acl" in issues:
                result = re.sub(r'acl\s*=\s*["\']public-read(-write)?["\']', 'acl = "private"', result)
            if "missing_encryption" in issues:
                result += '''
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }'''
            if "missing_public_access_block" in issues:
                pab_block = f'''
resource "aws_s3_bucket_public_access_block" "{bucket_name}_pab" {{
  bucket = aws_s3_bucket.{bucket_name}.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}'''
                return f'resource "aws_s3_bucket" "{bucket_name}" {{{result}}}\n{pab_block}'
        else:
            result += '''
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  tags = {
    PublicAccess = "intentional"
    Security = "hardened"
  }'''
        return f'resource "aws_s3_bucket" "{bucket_name}" {{{result}}}'

    def process_file(self, file_path):
        print(f"📂 Processing {file_path}")
        content = self.read_file_content(file_path)
        if not content:
            return

        fixed_content = content
        changes = []

        for bucket in self.find_s3_buckets(content):
            name = bucket['name']
            config = bucket['config']
            issues = self.check_bucket_security_issues(config)

            if not issues:
                continue

            self.issues_found.append({'bucket': name, 'issues': issues})

            if self.is_intentionally_public(name, config):
                fixed = self.generate_fixed_bucket(name, config, issues, intentional=True)
                print(f"🟡 {name} is intentionally public — hardened config generated.")
            else:
                fixed = self.generate_fixed_bucket(name, config, issues)
                print(f"🔧 Issues fixed for {name}: {', '.join(issues)}")

            fixed_content = fixed_content.replace(bucket['full_match'], fixed)
            changes.append({'bucket': name, 'issues': issues, 'fixed_config': fixed})

        if changes:
            filename = file_path.name
            output_path = self.fix_artifacts_dir / f"fixed_{filename}"
            with open(output_path, "w", encoding='utf-8') as f:
                f.write(fixed_content)
            self.fixes_applied.extend(changes)
            print(f"✅ Fix saved to {output_path}")

    def generate_report(self):
        report = "# 🛡️ S3 Remediation Report\n\n"
        report += f"**Run Time:** {datetime.now().isoformat()}\n\n"
        report += f"**Fixes Applied:** {len(self.fixes_applied)}\n\n"
        for fix in self.fixes_applied:
            report += f"## {fix['bucket']}\n- Issues: {', '.join(fix['issues'])}\n\n"
        with open(self.fix_artifacts_dir / "report.md", "w") as f:
            f.write(report)

    def run(self):
        files = self.scan_terraform_files()
        print(f"🔍 Found {len(files)} .tf files")
        for file in files:
            self.process_file(file)
        self.generate_report()
        print("✅ Done.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", default="terraform")
    parser.add_argument("--live", action="store_true", help="Actually modify files (non-dry-run)")
    args = parser.parse_args()

    dry_run = not args.live
    remediator = S3SecurityRemediator(source_dir=args.source_dir, dry_run=dry_run)
    remediator.run()

if __name__ == "__main__":
    main()

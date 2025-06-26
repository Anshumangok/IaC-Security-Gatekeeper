import os
import re
import json
from datetime import datetime
from typing import Dict, List, Tuple, Optional

SOURCE_DIR = "terraform"
OUTPUT_DIR = "fix_artifacts"
REPORT_FILE = "s3_remediation_report.md"

# Enhanced detection patterns for intentional public buckets
PUBLIC_INDICATORS = {
    "name_keywords": ["public", "cdn", "static", "assets", "website", "web", "frontend", "ui"],
    "tag_keys": ["public", "website", "cdn", "static", "web-hosting", "frontend"],
    "tag_values": ["public", "website", "static-hosting", "cdn", "web"],
    "comment_keywords": ["hosting", "public use", "cdn", "static hosting", "website", "web assets", "frontend"]
}

# Security policies for different bucket types
SECURITY_POLICIES = {
    "private": {
        "acl": "private",
        "public_access_block": True,
        "requires_ssl": True
    },
    "public_read": {
        "acl": "public-read",
        "public_access_block": False,
        "requires_ssl": True
    }
}

class S3BucketAnalyzer:
    def __init__(self):
        self.analysis_results = []
        self.fixed_files = []
        
    def has_public_acl(self, content: str) -> bool:
        """Check if content has public ACL configuration"""
        patterns = [
            r'acl\s*=\s*"public-read(-write)?"',
            r'acl\s*=\s*"authenticated-read"',
            r'grant.*uri.*AllUsers'
        ]
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns)
    
    def extract_bucket_config(self, content: str) -> Dict:
        """Extract bucket configuration details"""
        config = {
            "name": "unknown",
            "acl": None,
            "tags": {},
            "comments": [],
            "has_public_access_block": False,
            "has_bucket_policy": False
        }
        
        # Extract bucket name
        name_match = re.search(r'resource\s+"aws_s3_bucket"\s+"([^"]+)"', content)
        if name_match:
            config["name"] = name_match.group(1)
        
        # Extract ACL
        acl_match = re.search(r'acl\s*=\s*"([^"]+)"', content)
        if acl_match:
            config["acl"] = acl_match.group(1)
        
        # Extract tags
        tags_match = re.search(r'tags\s*=\s*{([^}]+)}', content, re.DOTALL)
        if tags_match:
            tags_content = tags_match.group(1)
            tag_pairs = re.findall(r'(\w+)\s*=\s*"([^"]+)"', tags_content)
            config["tags"] = {k: v for k, v in tag_pairs}
        
        # Check for public access block
        config["has_public_access_block"] = bool(re.search(r'aws_s3_bucket_public_access_block', content))
        
        # Check for bucket policy
        config["has_bucket_policy"] = bool(re.search(r'aws_s3_bucket_policy', content))
        
        return config
    
    def extract_comments_near_resource(self, lines: List[str], resource_line: int) -> List[str]:
        """Extract comments near the resource definition"""
        comments = []
        
        # Look backwards for comments
        for i in range(resource_line - 1, max(-1, resource_line - 10), -1):
            line = lines[i].strip()
            if line.startswith("#"):
                comments.insert(0, line[1:].strip())
            elif line and not line.isspace():
                break
        
        # Look forwards for inline comments
        for i in range(resource_line, min(len(lines), resource_line + 20)):
            line = lines[i]
            if "#" in line:
                comment_part = line.split("#", 1)[1].strip()
                if comment_part:
                    comments.append(comment_part)
        
        return comments
    
    def analyze_intent(self, bucket_name: str, tags: Dict, comments: List[str]) -> Tuple[bool, str, List[str]]:
        """Analyze if the bucket is intentionally public"""
        reasons = []
        is_intentional = False
        
        # Check bucket name
        name_lower = bucket_name.lower()
        for keyword in PUBLIC_INDICATORS["name_keywords"]:
            if keyword in name_lower:
                reasons.append(f"Bucket name contains '{keyword}'")
                is_intentional = True
        
        # Check tags
        for tag_key, tag_value in tags.items():
            key_lower, value_lower = tag_key.lower(), tag_value.lower()
            
            if key_lower in PUBLIC_INDICATORS["tag_keys"]:
                reasons.append(f"Tag key '{tag_key}' indicates public use")
                is_intentional = True
            
            if value_lower in PUBLIC_INDICATORS["tag_values"]:
                reasons.append(f"Tag value '{tag_value}' indicates public use")
                is_intentional = True
        
        # Check comments
        comment_text = " ".join(comments).lower()
        for keyword in PUBLIC_INDICATORS["comment_keywords"]:
            if keyword in comment_text:
                reasons.append(f"Comments mention '{keyword}'")
                is_intentional = True
        
        confidence = "high" if len(reasons) >= 2 else "medium" if len(reasons) == 1 else "low"
        
        return is_intentional, confidence, reasons
    
    def generate_secure_config(self, original_config: Dict, is_public: bool) -> str:
        """Generate secure Terraform configuration"""
        policy = SECURITY_POLICIES["public_read" if is_public else "private"]
        bucket_name = original_config["name"]
        
        config_lines = []
        
        # Main bucket resource
        config_lines.append(f'resource "aws_s3_bucket" "{bucket_name}" {{')
        config_lines.append(f'  bucket = "{bucket_name}"')
        
        # Add original tags plus security tags
        tags = original_config["tags"].copy()
        tags["ManagedBy"] = "SecurityGatekeeper"
        tags["LastRemediated"] = datetime.now().strftime("%Y-%m-%d")
        
        if tags:
            config_lines.append('  tags = {')
            for key, value in tags.items():
                config_lines.append(f'    {key} = "{value}"')
            config_lines.append('  }')
        
        config_lines.append('}')
        config_lines.append('')
        
        # ACL resource (separate as per AWS provider v4+)
        config_lines.append(f'resource "aws_s3_bucket_acl" "{bucket_name}_acl" {{')
        config_lines.append(f'  bucket = aws_s3_bucket.{bucket_name}.id')
        config_lines.append(f'  acl    = "{policy["acl"]}"')
        config_lines.append('}')
        config_lines.append('')
        
        # Public access block (always recommended)
        if policy["public_access_block"]:
            config_lines.append(f'resource "aws_s3_bucket_public_access_block" "{bucket_name}_pab" {{')
            config_lines.append(f'  bucket = aws_s3_bucket.{bucket_name}.id')
            config_lines.append('')
            config_lines.append('  block_public_acls       = true')
            config_lines.append('  block_public_policy     = true')
            config_lines.append('  ignore_public_acls      = true')
            config_lines.append('  restrict_public_buckets = true')
            config_lines.append('}')
            config_lines.append('')
        
        # Server-side encryption
        config_lines.append(f'resource "aws_s3_bucket_server_side_encryption_configuration" "{bucket_name}_encryption" {{')
        config_lines.append(f'  bucket = aws_s3_bucket.{bucket_name}.id')
        config_lines.append('')
        config_lines.append('  rule {')
        config_lines.append('    apply_server_side_encryption_by_default {')
        config_lines.append('      sse_algorithm = "AES256"')
        config_lines.append('    }')
        config_lines.append('  }')
        config_lines.append('}')
        config_lines.append('')
        
        # Versioning
        config_lines.append(f'resource "aws_s3_bucket_versioning" "{bucket_name}_versioning" {{')
        config_lines.append(f'  bucket = aws_s3_bucket.{bucket_name}.id')
        config_lines.append('  versioning_configuration {')
        config_lines.append('    status = "Enabled"')
        config_lines.append('  }')
        config_lines.append('}')
        
        return '\n'.join(config_lines)
    
    def process_terraform_files(self) -> None:
        """Process all Terraform files and fix S3 misconfigurations"""
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        for root, _, files in os.walk(SOURCE_DIR):
            for file in files:
                if not file.endswith('.tf'):
                    continue
                
                file_path = os.path.join(root, file)
                self._process_single_file(file_path, file)
    
    def _process_single_file(self, file_path: str, filename: str) -> None:
        """Process a single Terraform file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                content = ''.join(lines)
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return
        
        if not self.has_public_acl(content):
            return
        
        # Find S3 bucket resources
        bucket_resources = list(re.finditer(r'resource\s+"aws_s3_bucket"\s+"([^"]+)"', content))
        
        for match in bucket_resources:
            bucket_name = match.group(1)
            resource_line = content[:match.start()].count('\n')
            
            # Extract configuration
            config = self.extract_bucket_config(content)
            config["name"] = bucket_name
            
            # Extract comments
            comments = self.extract_comments_near_resource(lines, resource_line)
            
            # Analyze intent
            is_intentional, confidence, reasons = self.analyze_intent(
                bucket_name, config["tags"], comments
            )
            
            # Record analysis
            analysis = {
                "file": filename,
                "bucket_name": bucket_name,
                "original_acl": config["acl"],
                "is_intentional_public": is_intentional,
                "confidence": confidence,
                "reasons": reasons,
                "action": "skipped" if is_intentional else "fixed"
            }
            self.analysis_results.append(analysis)
            
            # Generate fixed configuration
            if not is_intentional:
                secure_config = self.generate_secure_config(config, False)
                self._save_fixed_file(filename, secure_config)
                analysis["action"] = "fixed"
            else:
                # Still generate a secure public configuration
                secure_config = self.generate_secure_config(config, True) 
                self._save_fixed_file(f"public_{filename}", secure_config)
                analysis["action"] = "secured_public"
    
    def _save_fixed_file(self, filename: str, content: str) -> None:
        """Save fixed configuration to output directory"""
        output_path = os.path.join(OUTPUT_DIR, filename)
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
            self.fixed_files.append(filename)
        except Exception as e:
            print(f"Error saving {output_path}: {e}")
    
    def generate_report(self) -> None:
        """Generate a comprehensive remediation report"""
        report_path = os.path.join(OUTPUT_DIR, REPORT_FILE)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("# 🛡️ S3 Security Remediation Report\n\n")
            f.write(f"*Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
            
            # Summary
            total = len(self.analysis_results)
            fixed = len([r for r in self.analysis_results if r["action"] == "fixed"])
            skipped = len([r for r in self.analysis_results if r["action"] == "skipped"])
            secured_public = len([r for r in self.analysis_results if r["action"] == "secured_public"])
            
            f.write("## 📊 Summary\n\n")
            f.write(f"- **Total Buckets Analyzed**: {total}\n")
            f.write(f"- **🔒 Fixed (Made Private)**: {fixed}\n")
            f.write(f"- **🔐 Secured Public**: {secured_public}\n")
            f.write(f"- **⏭️ Skipped (Intentional)**: {skipped}\n")
            f.write(f"- **📁 Files Generated**: {len(self.fixed_files)}\n\n")
            
            # Detailed results
            f.write("## 🔍 Detailed Analysis\n\n")
            f.write("| Bucket | File | Original ACL | Action | Confidence | Reasons |\n")
            f.write("|--------|------|--------------|--------|------------|----------|\n")
            
            for result in self.analysis_results:
                action_emoji = {
                    "fixed": "🔒",
                    "secured_public": "🔐", 
                    "skipped": "⏭️"
                }.get(result["action"], "❓")
                
                reasons_text = "; ".join(result["reasons"]) if result["reasons"] else "None"
                
                f.write(f"| `{result['bucket_name']}` | `{result['file']}` | "
                       f"`{result['original_acl']}` | {action_emoji} {result['action']} | "
                       f"{result['confidence']} | {reasons_text} |\n")
            
            # Security improvements applied
            f.write("\n## 🛡️ Security Improvements Applied\n\n")
            f.write("For all remediated buckets, the following security measures were implemented:\n\n")
            f.write("- ✅ **Encryption**: Server-side encryption enabled (AES256)\n")
            f.write("- ✅ **Versioning**: Object versioning enabled\n")
            f.write("- ✅ **Access Control**: Appropriate ACL settings\n")
            f.write("- ✅ **Public Access Block**: Configured for private buckets\n")
            f.write("- ✅ **Tagging**: Security management tags added\n\n")
            
            # Next steps
            f.write("## 🚀 Next Steps\n\n")
            f.write("1. Review the generated configurations in the `fix_artifacts/` directory\n")
            f.write("2. Test the configurations in a development environment\n")
            f.write("3. Apply the changes using `terraform plan` and `terraform apply`\n")
            f.write("4. Monitor bucket access patterns after changes\n")
            f.write("5. Update your CI/CD pipeline to prevent future misconfigurations\n")

def main():
    """Main execution function"""
    print("🔍 Starting S3 Security Remediation...")
    
    analyzer = S3BucketAnalyzer()
    analyzer.process_terraform_files()
    analyzer.generate_report()
    
    total_analyzed = len(analyzer.analysis_results)
    total_fixed = len(analyzer.fixed_files)
    
    print(f"✅ Remediation complete!")
    print(f"   📁 Files analyzed: {total_analyzed}")
    print(f"   🔧 Configurations generated: {total_fixed}")
    print(f"   📋 Report saved to: {OUTPUT_DIR}/{REPORT_FILE}")

if __name__ == "__main__":
    main()
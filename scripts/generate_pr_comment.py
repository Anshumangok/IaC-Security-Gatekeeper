#!/usr/bin/env python3
"""
Production PR Comment Generator for IaC Security Gatekeeper
Generates PR comments with security findings and fix suggestions
"""

import json
import sys
import os
from pathlib import Path

# Import fix snippets
try:
    from fix_snippets import FIX_SNIPPETS
except ImportError:
    print("Warning: fix_snippets.py not found, using empty fix snippets")
    FIX_SNIPPETS = {}

# File paths
CHECKOV_JSON = Path("checkov_reports/report.json")
COMMENT_FILE = Path("checkov_reports/pr_comment.md")

# Emojis as Unicode escape sequences for compatibility
EMOJIS = {
    'shield': '\U0001F6E1\uFE0F',    # 🛡️
    'check': '\U00002705',           # ✅  
    'warning': '\U000026A0\uFE0F',   # ⚠️
    'bulb': '\U0001F4A1',            # 💡
    'lock': '\U0001F512',            # 🔒
    'fire': '\U0001F525',            # 🔥
    'wrench': '\U0001F527',          # 🔧
}

# Severity emojis
SEVERITY_EMOJIS = {
    'CRITICAL': '\U0001F534',  # 🔴
    'HIGH': '\U0001F7E0',      # 🟠
    'MEDIUM': '\U0001F7E1',    # 🟡
    'LOW': '\U0001F535',       # 🔵
    'INFO': '\U0001F7E2',      # 🟢
    'UNKNOWN': '\U000026AB'    # ⚫
}

def load_checkov_results():
    """Load Checkov results with robust error handling."""
    try:
        if not CHECKOV_JSON.exists():
            print(f"❌ Checkov report not found at {CHECKOV_JSON}")
            return []
        
        print(f"📄 Loading Checkov results from {CHECKOV_JSON}")
        
        with open(CHECKOV_JSON, encoding='utf-8') as f:
            content = f.read().strip()
            
        if not content:
            print("⚠️ Checkov report is empty")
            return []
        
        # Parse JSON
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON in Checkov report: {e}")
            print("First 200 chars of content:")
            print(repr(content[:200]))
            return []
        
        # Extract failed checks from various JSON structures
        failed_checks = []
        
        if isinstance(data, dict):
            # Standard Checkov format: {"results": {"failed_checks": [...]}}
            if "results" in data and isinstance(data["results"], dict):
                failed_checks = data["results"].get("failed_checks", [])
                print(f"📊 Found {len(failed_checks)} failed checks in 'results' format")
            
            # Direct format: {"failed_checks": [...]}
            elif "failed_checks" in data:
                failed_checks = data.get("failed_checks", [])
                print(f"📊 Found {len(failed_checks)} failed checks in direct format")
            
            # Framework-specific format
            elif any(key.startswith("terraform") for key in data.keys()):
                for key, value in data.items():
                    if isinstance(value, dict) and "failed_checks" in value:
                        failed_checks.extend(value.get("failed_checks", []))
                print(f"📊 Found {len(failed_checks)} failed checks in framework format")
        
        elif isinstance(data, list):
            # Array of results
            for item in data:
                if isinstance(item, dict):
                    if "results" in item:
                        failed_checks.extend(item["results"].get("failed_checks", []))
                    elif "failed_checks" in item:
                        failed_checks.extend(item.get("failed_checks", []))
            print(f"📊 Found {len(failed_checks)} failed checks in array format")
        
        return failed_checks
        
    except Exception as e:
        print(f"❌ Error loading Checkov results: {e}")
        return []

def get_fix_snippet(check_id, bucket_name):
    """Get fix snippet for a specific check ID."""
    template = FIX_SNIPPETS.get(check_id)
    if not template:
        return f"```hcl\n# No automated fix available for {check_id}\n# Please refer to Checkov documentation for manual remediation\n```"
    
    try:
        return template.format(bucket_name=bucket_name)
    except Exception as e:
        print(f"⚠️ Error formatting fix snippet for {check_id}: {e}")
        return f"```hcl\n# Fix template error for {check_id}\n```"

def extract_resource_name(resource_id):
    """Extract resource name from resource ID for fix snippets."""
    if not resource_id:
        return "resource"
    
    # Handle formats like: aws_s3_bucket.bucket_name
    if "." in resource_id:
        parts = resource_id.split(".")
        return parts[-1] if len(parts) >= 2 else "resource"
    
    return resource_id

def get_severity_info(check):
    """Get severity information with fallback."""
    severity = check.get("severity", "").upper()
    
    # Fallback severity mapping for common checks
    severity_fallback = {
        "CKV_AWS_20": "HIGH",    # S3 public read
        "CKV_AWS_21": "HIGH",    # S3 encryption
        "CKV2_AWS_6": "HIGH",    # S3 public access block
        "CKV_AWS_18": "MEDIUM",  # S3 access logging
        "CKV_AWS_19": "HIGH",    # S3 SSL only
    }
    
    if not severity or severity == "UNKNOWN":
        check_id = check.get("check_id", "")
        severity = severity_fallback.get(check_id, "MEDIUM")
    
    emoji = SEVERITY_EMOJIS.get(severity, SEVERITY_EMOJIS['UNKNOWN'])
    return severity, emoji

def format_file_path(file_path):
    """Format file path for display."""
    if not file_path:
        return "Unknown file"
    
    # Show relative path from repository root
    path = Path(file_path)
    if len(path.parts) > 3:
        return f".../{'/'.join(path.parts[-2:])}"
    return str(path)

def generate_pr_comment(failed_checks):
    """Generate comprehensive PR comment."""
    lines = []
    
    # Header
    lines.extend([
        f"# {EMOJIS['shield']} IaC Security Scan Report",
        "",
        f"**Scan completed:** {len(failed_checks)} security issue(s) detected",
        ""
    ])
    
    if not failed_checks:
        lines.extend([
            f"{EMOJIS['check']} **Congratulations!** All security checks passed.",
            "",
            "Your infrastructure code follows security best practices. Great job! {EMOJIS['fire']}",
            "",
            "---",
            "*Automatically generated by IaC Security Gatekeeper*"
        ])
    else:
        # Group by severity
        severity_groups = {}
        for check in failed_checks:
            severity, _ = get_severity_info(check)
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(check)
        
        # Summary table
        lines.extend([
            "## {EMOJIS['warning']} Security Issues Summary",
            "",
            "| Severity | Count | Action Required |",
            "|----------|--------|-----------------|"
        ])
        
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        total_critical_high = 0
        
        for severity in severity_order:
            if severity in severity_groups:
                count = len(severity_groups[severity])
                _, emoji = get_severity_info({'severity': severity})
                
                if severity in ['CRITICAL', 'HIGH']:
                    total_critical_high += count
                    action = "🚨 **Immediate**"
                elif severity == 'MEDIUM':
                    action = "⏰ Soon"
                else:
                    action = "📝 When convenient"
                
                lines.append(f"| {emoji} {severity} | {count} | {action} |")
        
        lines.extend(["", ""])
        
        # Critical/High priority callout
        if total_critical_high > 0:
            lines.extend([
                f"> {EMOJIS['fire']} **{total_critical_high} high-priority security issue(s) require immediate attention!**",
                ""
            ])
        
        # Detailed findings
        lines.extend([
            f"## {EMOJIS['lock']} Detailed Findings",
            ""
        ])
        
        issue_counter = 1
        for severity in severity_order:
            if severity not in severity_groups:
                continue
                
            severity_checks = severity_groups[severity]
            _, emoji = get_severity_info({'severity': severity})
            
            lines.extend([
                f"### {emoji} {severity} Priority Issues ({len(severity_checks)})",
                ""
            ])
            
            for check in severity_checks:
                check_id = check.get("check_id", "Unknown")
                check_name = check.get("check_name", "Unnamed security check")
                file_path = format_file_path(check.get("file_path"))
                resource = check.get("resource", "unknown.resource")
                description = check.get("description", "").strip()
                
                # Get line information
                line_range = check.get("file_line_range", [])
                line_info = ""
                if line_range and len(line_range) >= 2:
                    if line_range[0] == line_range[-1]:
                        line_info = f" (line {line_range[0]})"
                    else:
                        line_info = f" (lines {line_range[0]}-{line_range[-1]})"
                
                lines.extend([
                    f"#### {issue_counter}. {check_name}",
                    "",
                    f"- **Check ID:** `{check_id}`",
                    f"- **File:** `{file_path}`{line_info}",
                    f"- **Resource:** `{resource}`"
                ])
                
                if description:
                    lines.append(f"- **Issue:** {description}")
                
                # Add fix suggestion
                resource_name = extract_resource_name(resource)
                fix_snippet = get_fix_snippet(check_id, resource_name)
                
                lines.extend([
                    "",
                    f"**{EMOJIS['bulb']} Suggested Fix:**",
                    fix_snippet,
                    "",
                    "---",
                    ""
                ])
                
                issue_counter += 1
        
        # Footer with next steps
        lines.extend([
            f"## {EMOJIS['wrench']} Next Steps",
            "",
            "1. **Review** each security issue above",
            "2. **Apply** the suggested fixes to your code",
            "3. **Test** your changes in a development environment", 
            "4. **Commit** the security improvements",
            "",
            f"Questions? Check the [Checkov documentation](https://www.checkov.io/5.Policy%20Index/terraform.html) for detailed explanations.",
            "",
            "---",
            "*This comment was automatically generated by IaC Security Gatekeeper*"
        ])
    
    return "\n".join(lines)

def main():
    """Main function."""
    print("🚀 Starting PR comment generation...")
    
    try:
        # Ensure output directory exists
        COMMENT_FILE.parent.mkdir(exist_ok=True)
        
        # Load Checkov results
        failed_checks = load_checkov_results()
        
        # Generate comment
        print(f"📝 Generating PR comment for {len(failed_checks)} issues...")
        comment_content = generate_pr_comment(failed_checks)
        
        # Write comment to file
        with open(COMMENT_FILE, 'w', encoding='utf-8') as f:
            f.write(comment_content)
        
        print(f"✅ PR comment generated successfully!")
        print(f"📄 Comment saved to: {COMMENT_FILE}")
        print(f"📊 Comment size: {len(comment_content)} characters")
        
        # Verify file was created
        if COMMENT_FILE.exists() and COMMENT_FILE.stat().st_size > 0:
            print("✅ Comment file verification passed")
        else:
            print("❌ Comment file verification failed")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ Fatal error generating PR comment: {e}")
        
        # Create minimal fallback comment
        try:
            fallback_content = f"""# {EMOJIS['warning']} IaC Security Scan

Security scan completed, but there was an issue generating the detailed report.

**Error:** {str(e)[:100]}...

Please check the workflow logs and artifacts for more details.

---
*Generated by IaC Security Gatekeeper*"""
            
            with open(COMMENT_FILE, 'w', encoding='utf-8') as f:
                f.write(fallback_content)
            print("✅ Fallback comment created")
            
        except Exception as fallback_error:
            print(f"❌ Failed to create fallback comment: {fallback_error}")
            sys.exit(1)

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Generate Markdown Report from Checkov JSON Results
"""

import json
import os
from datetime import datetime
from pathlib import Path

# Optional severity fallback if missing
CHECKOV_SEVERITY_MAP = {
    # --- AWS S3 ---
    "CKV_AWS_18": "LOW",           # Access logging
    "CKV_AWS_20": "HIGH",          # Unrestricted public bucket
    "CKV_AWS_21": "HIGH",          # Unencrypted S3 bucket
    "CKV_AWS_144": "MEDIUM",       # Cross-region replication
    "CKV_AWS_145": "HIGH",         # Default encryption
    "CKV_AWS_19": "HIGH",          # SSL-only bucket policy

    # --- AWS S3 Extended ---
    "CKV2_AWS_6": "HIGH",          # Public Access Block
    "CKV2_AWS_61": "LOW",          # Lifecycle configuration
    "CKV2_AWS_62": "MEDIUM",       # Event notification

    # --- AWS General ---
    "CKV_AWS_23": "HIGH",          # Unrestricted SG ingress
    "CKV_AWS_117": "HIGH",         # IAM policy allows *
    "CKV_AWS_111": "HIGH",         # No MFA on IAM users
    "CKV_AWS_16": "HIGH",          # RDS not encrypted
    "CKV_AWS_79": "HIGH",          # Secrets in plain text

    # --- Kubernetes: General Security ---
    "CKV_K8S_8": "MEDIUM",         # Liveness probe
    "CKV_K8S_9": "MEDIUM",         # Readiness probe
    "CKV_K8S_10": "MEDIUM",        # CPU requests
    "CKV_K8S_11": "MEDIUM",        # CPU limits
    "CKV_K8S_12": "MEDIUM",        # Memory requests
    "CKV_K8S_13": "MEDIUM",        # Memory limits
    "CKV_K8S_14": "LOW",           # Image tag not pinned
    "CKV_K8S_20": "HIGH",          # allowPrivilegeEscalation
    "CKV_K8S_21": "LOW",           # Default namespace
    "CKV_K8S_22": "LOW",           # Read-only root filesystem
    "CKV_K8S_23": "HIGH",          # Containers run as root
    "CKV_K8S_28": "HIGH",          # Minimize capabilities
    "CKV_K8S_29": "HIGH",          # Pod security context
    "CKV_K8S_30": "HIGH",          # Container security context
    "CKV_K8S_31": "MEDIUM",        # Seccomp profile
    "CKV_K8S_37": "HIGH",          # Capabilities - restrict admission
    "CKV_K8S_38": "MEDIUM",        # Automount ServiceAccountToken
    "CKV_K8S_40": "MEDIUM",        # High UID user
    "CKV_K8S_43": "LOW",           # Use image digest

    # --- Kubernetes RBAC / Secrets ---
    "CKV_K8S_6": "HIGH",           # Secret mounted as env var
    "CKV_K8S_7": "HIGH",           # RBAC rules overly permissive

    # --- GitHub Workflows ---
    "CKV2_GHA_1": "LOW",           # Top-level permissions not set
    "CKV_GHA_2": "MEDIUM",         # Untrusted actions

    # --- Docker ---
    "CKV_DOCKER_2": "HIGH",        # Use latest image
    "CKV_DOCKER_3": "MEDIUM",      # USER not set in Dockerfile

    # --- Terraform Linting ---
    "CKV_TF_1": "LOW",             # Missing description
}


def get_severity(check):
    """Get severity from check, with fallback to predefined map."""
    severity = check.get("severity", "UNKNOWN")
    if severity == "UNKNOWN" or not severity:
        severity = CHECKOV_SEVERITY_MAP.get(check.get("check_id", ""), "UNKNOWN")
    return severity.upper()


def truncate(text, limit=40):
    """Truncate text to specified limit."""
    return text if len(text) <= limit else text[:limit-3] + "..."


def extract_filename(path):
    """Extract filename from path."""
    return os.path.basename(path) if path else "N/A"


def parse_checkov_data(data):
    """Parse Checkov data regardless of format (dict or list)."""
    failed, passed = [], []

    if isinstance(data, dict):
        if "results" in data:
            failed = data["results"].get("failed_checks", [])
            passed = data["results"].get("passed_checks", [])
        elif "failed_checks" in data:
            failed = data.get("failed_checks", [])
            passed = data.get("passed_checks", [])
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                if "results" in item:
                    failed.extend(item["results"].get("failed_checks", []))
                    passed.extend(item["results"].get("passed_checks", []))
                elif "failed_checks" in item:
                    failed.extend(item.get("failed_checks", []))
                    passed.extend(item.get("passed_checks", []))

    return failed, passed


def load_checkov_report():
    """Load the Checkov JSON report."""
    report_path = Path("checkov_reports/report.json")
    if not report_path.exists():
        print(f"Checkov report not found at {report_path}")
        return None
    
    try:
        with open(report_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading Checkov report: {e}")
        return None


def generate_comprehensive_report(failed_checks, passed_checks):
    """Generate comprehensive markdown report."""
    report = "# 🛡️ Checkov IaC Security Scan Report\n\n"
    report += f"_Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_\n\n"
    report += f"- ✅ **Passed Checks**: {len(passed_checks)}\n"
    report += f"- ❌ **Failed Checks**: {len(failed_checks)}\n"
    report += f"- 📝 **Total Checks**: {len(failed_checks) + len(passed_checks)}\n\n"

    if not failed_checks:
        report += "## 🎉 All checks passed! No misconfigurations detected.\n"
        return report

    report += "## ❌ Failed Checks\n\n"
    report += "| # | Severity | Check ID | Name | File | Resource | Lines |\n"
    report += "|---|----------|----------|------|------|----------|-------|\n"

    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    failed_sorted = sorted(failed_checks, key=lambda x: (
        severity_rank.get(get_severity(x), 5),
        x.get("check_name", "")
    ))

    for i, check in enumerate(failed_sorted, 1):
        severity = get_severity(check)
        check_id = check.get("check_id", "N/A")
        name = truncate(check.get("check_name", "Unnamed"))
        filename = extract_filename(check.get("file_path"))
        resource = truncate(check.get("resource", "N/A"), 30)
        lines = check.get("file_line_range", [])
        line_range = f"{lines[0]}-{lines[-1]}" if lines else "N/A"

        emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "UNKNOWN": "⚫"
        }.get(severity, "⚫")

        report += f"| {i} | {emoji} {severity} | `{check_id}` | {name} | `{filename}` | {resource} | {line_range} |\n"

    return report


def generate_s3_focused_report(failed_checks, passed_checks):
    """Generate S3-focused markdown report."""
    # Filter for S3-related checks
    s3_failed = [check for check in failed_checks if 
                 'S3' in check.get('check_name', '').upper() or 
                 'BUCKET' in check.get('check_name', '').upper() or
                 check.get('check_id', '') in ['CKV_AWS_20', 'CKV_AWS_21', 'CKV2_AWS_6', 'CKV_AWS_18', 'CKV_AWS_19', 'CKV_AWS_144', 'CKV_AWS_145']]
    
    report = f"""# 🛡️ S3 Security Scan Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

## 📊 Summary

- **Total Failed Checks:** {len(failed_checks)}
- **S3-Related Issues:** {len(s3_failed)}
- **Total Passed Checks:** {len(passed_checks)}

## 🚨 S3 Security Issues Found

"""
    
    if not s3_failed:
        report += "✅ **No S3 security issues detected!**\n"
    else:
        for check in s3_failed:
            report += f"""### {check.get('check_name', 'Unknown Check')}

- **Check ID:** `{check.get('check_id', 'N/A')}`
- **File:** `{check.get('file_path', 'N/A')}`
- **Resource:** `{check.get('resource', 'N/A')}`
- **Severity:** {get_severity(check)}

**Description:** {check.get('description', 'No description available')}

---

"""
    
    report += f"""
## 🔧 Remediation Actions

{len(s3_failed)} S3 security issues require attention:

1. **Public Bucket ACLs (CKV_AWS_20)**: Change public bucket ACLs to private
2. **Missing Encryption (CKV_AWS_21)**: Enable server-side encryption
3. **Public Access Blocks (CKV2_AWS_6)**: Implement comprehensive public access blocks

## 📋 Next Steps

1. Review each failed check above
2. Run the S3 remediation workflow to generate fixes
3. Test the generated configurations
4. Apply the security improvements

---
*Generated by Security Gatekeeper*
"""
    
    return report


def main():
    """Main function to generate the report."""
    print("📋 Generating security scan report...")
    
    # Load Checkov data
    checkov_data = load_checkov_report()
    if not checkov_data:
        print("❌ No Checkov data available")
        return

    # Parse the data using the robust parser
    failed_checks, passed_checks = parse_checkov_data(checkov_data)
    
    print(f"📊 Found {len(failed_checks)} failed checks and {len(passed_checks)} passed checks")
    
    # Create reports directory
    report_dir = Path("checkov_reports")
    report_dir.mkdir(exist_ok=True)
    
    # Generate comprehensive report
    comprehensive_report = generate_comprehensive_report(failed_checks, passed_checks)
    comprehensive_path = report_dir / "report.md"
    with open(comprehensive_path, 'w', encoding='utf-8') as f:
        f.write(comprehensive_report)
    print(f"✅ Comprehensive report generated: {comprehensive_path}")
    
    # Generate S3-focused report
    s3_report = generate_s3_focused_report(failed_checks, passed_checks)
    s3_path = report_dir / "security_report.md"
    with open(s3_path, 'w', encoding='utf-8') as f:
        f.write(s3_report)
    print(f"✅ S3-focused report generated: {s3_path}")


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
import json
import os
from datetime import datetime

# Severity mapping based on your requirements
CHECKOV_SEVERITY_MAP = {
    # --- AWS S3 ---
    "CKV_AWS_18": "LOW",      # Access logging
    "CKV_AWS_20": "HIGH",     # Unrestricted public bucket
    "CKV_AWS_21": "HIGH",     # Unencrypted S3 bucket
    "CKV_AWS_144": "MEDIUM",  # Cross-region replication
    "CKV_AWS_145": "HIGH",    # Default encryption
    "CKV_AWS_19": "HIGH",     # SSL-only bucket policy
    # --- AWS S3 Extended ---
    "CKV2_AWS_6": "HIGH",     # Public Access Block
    "CKV2_AWS_61": "LOW",     # Lifecycle configuration
    "CKV2_AWS_62": "MEDIUM",  # Event notification
    # --- AWS General ---
    "CKV_AWS_23": "HIGH",     # Unrestricted SG ingress
    "CKV_AWS_117": "HIGH",    # IAM policy allows *
    "CKV_AWS_111": "HIGH",    # No MFA on IAM users
    "CKV_AWS_16": "HIGH",     # RDS not encrypted
    "CKV_AWS_79": "HIGH",     # Secrets in plain text
    # --- Kubernetes: General Security ---
    "CKV_K8S_8": "MEDIUM",    # Liveness probe
    "CKV_K8S_9": "MEDIUM",    # Readiness probe
    "CKV_K8S_10": "MEDIUM",   # CPU requests
    "CKV_K8S_11": "MEDIUM",   # CPU limits
    "CKV_K8S_12": "MEDIUM",   # Memory requests
    "CKV_K8S_13": "MEDIUM",   # Memory limits
    "CKV_K8S_14": "LOW",      # Image tag not pinned
    "CKV_K8S_20": "HIGH",     # allowPrivilegeEscalation
    "CKV_K8S_21": "LOW",      # Default namespace
    "CKV_K8S_22": "LOW",      # Read-only root filesystem
    "CKV_K8S_23": "HIGH",     # Containers run as root
    "CKV_K8S_28": "HIGH",     # Minimize capabilities
    "CKV_K8S_29": "HIGH",     # Pod security context
    "CKV_K8S_30": "HIGH",     # Container security context
    "CKV_K8S_31": "MEDIUM",   # Seccomp profile
    "CKV_K8S_37": "HIGH",     # Capabilities - restrict admission
    "CKV_K8S_38": "MEDIUM",   # Automount ServiceAccountToken
    "CKV_K8S_40": "MEDIUM",   # High UID user
    "CKV_K8S_43": "LOW",      # Use image digest
    # --- Kubernetes RBAC / Secrets ---
    "CKV_K8S_6": "HIGH",      # Secret mounted as env var
    "CKV_K8S_7": "HIGH",      # RBAC rules overly permissive
    # --- GitHub Workflows ---
    "CKV2_GHA_1": "LOW",      # Top-level permissions not set
    "CKV_GHA_2": "MEDIUM",    # Untrusted actions
    # --- Docker ---
    "CKV_DOCKER_2": "HIGH",   # Use latest image
    "CKV_DOCKER_3": "MEDIUM", # USER not set in Dockerfile
    # --- Terraform Linting ---
    "CKV_TF_1": "LOW",        # Missing description
}

def get_severity_emoji(severity):
    """Return emoji for severity level"""
    return {
        "HIGH": "🟠",
        "MEDIUM": "🟡", 
        "LOW": "🔵",
        "CRITICAL": "🔴"
    }.get(severity.upper(), "🚨")

def get_check_severity(check_id):
    """Get severity for a check ID"""
    return CHECKOV_SEVERITY_MAP.get(check_id, "MEDIUM")

def truncate_text(text, max_length=30):
    """Truncate text to specified length"""
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."

def parse_checkov_report(report_path):
    """Parse Checkov JSON report and generate markdown"""
    
    # Check if path exists and is a file
    if not os.path.exists(report_path):
        return "❌ Checkov report file not found!"
    
    if os.path.isdir(report_path):
        return f"❌ Expected file but found directory: {report_path}"
    
    try:
        with open(report_path, 'r') as f:
            content = f.read().strip()
            if not content:
                return "❌ Checkov report file is empty!"
            data = json.loads(content)
    except json.JSONDecodeError as e:
        return f"❌ Invalid JSON in Checkov report: {e}"
    except Exception as e:
        return f"❌ Error reading Checkov report: {e}"
    
    # Handle both list and dict formats from Checkov
    if isinstance(data, list):
        # If data is a list, find the first item with results
        results = {}
        for item in data:
            if isinstance(item, dict) and "results" in item:
                results = item.get("results", {})
                break
        # If no results found in list items, treat the list as failed_checks
        if not results:
            passed_checks = []
            failed_checks = data if isinstance(data, list) else []
        else:
            passed_checks = results.get("passed_checks", [])
            failed_checks = results.get("failed_checks", [])
    else:
        # Handle dictionary format
        results = data.get("results", {})
        passed_checks = results.get("passed_checks", [])
        failed_checks = results.get("failed_checks", [])
    
    passed_count = len(passed_checks)
    failed_count = len(failed_checks)
    total_count = passed_count + failed_count
    
    # Generate timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Build markdown report
    report = f"""# 🛡️ Checkov IaC Security Scan Report

_Generated on {timestamp}_

- ✅ **Passed Checks**: {passed_count}
- ❌ **Failed Checks**: {failed_count}
- 📝 **Total Checks**: {total_count}
"""
    
    if failed_count == 0:
        report += "\n🎉 **All checks passed!** Your infrastructure is secure.\n"
        return report
    
    # Add failed checks table
    report += "\n## ❌ Failed Checks\n\n"
    report += "| # | Severity | Check ID | Name | File | Resource | Lines |\n"
    report += "|---|----------|----------|------|------|----------|-------|\n"
    
    for i, check in enumerate(failed_checks, 1):
        check_id = check.get("check_id", "N/A")
        check_name = check.get("check_name", "Unknown Check")
        file_path = check.get("file_path", "N/A")
        resource = check.get("resource", "N/A")
        
        # Get line range
        line_range = check.get("file_line_range", [0, 0])
        if isinstance(line_range, list) and len(line_range) >= 2:
            lines = f"{line_range[0]}-{line_range[1]}"
        else:
            lines = "N/A"
        
        # Get severity using custom mapping
        severity = get_check_severity(check_id)
        severity_emoji = get_severity_emoji(severity)
        
        # Truncate long names
        short_name = truncate_text(check_name, 30)
        
        report += f"| {i} | {severity_emoji} {severity} | {check_id} | {short_name} | {file_path} | {resource} | {lines} |\n"
    
    return report

def main():
    """Main function to generate the report"""
    
    # Ensure output directory exists
    os.makedirs("checkov_reports", exist_ok=True)
    
    # Parse report and generate markdown
    report_content = parse_checkov_report("checkov_reports/report.json")
    
    # Write markdown report
    output_path = "checkov_reports/report.md"
    try:
        with open(output_path, 'w') as f:
            f.write(report_content)
        print(f"✅ Markdown report generated: {output_path}")
        print("\n" + "="*50)
        print(report_content)
        print("="*50)
    except Exception as e:
        print(f"❌ Error writing report: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
import json
import os
from datetime import datetime
import sys

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
    severity = check.get("severity", "UNKNOWN")
    if severity == "UNKNOWN" or not severity:
        severity = CHECKOV_SEVERITY_MAP.get(check.get("check_id", ""), "UNKNOWN")
    return severity.upper()

def truncate(text, limit=40):
    return text if len(text) <= limit else text[:limit-3] + "..."

def extract_filename(path):
    return os.path.basename(path) if path else "N/A"

def parse_checkov_report(json_path="checkov_reports/report.json"):
    if not os.path.exists(json_path):
        return "# ❌ Checkov Report Missing\n\nCould not find Checkov JSON report."

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return f"# ❌ Invalid JSON Report\n\nError: {e}"

    # Detect format
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
            if "results" in item:
                failed.extend(item["results"].get("failed_checks", []))

    return generate_markdown_report(failed, passed)

def generate_markdown_report(failed_checks, passed_checks):
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

def main():
    os.makedirs("checkov_reports", exist_ok=True)
    output_path = "checkov_reports/report.md"
    report = parse_checkov_report()

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"[✅] Markdown report saved to {output_path}")

if __name__ == "__main__":
    main()

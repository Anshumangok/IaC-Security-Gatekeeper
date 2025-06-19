import json
import os
from datetime import datetime

def parse_checkov_report(path):
    with open(path, 'r') as f:
        data = json.load(f)

    if not data or "results" not in data or not data["results"].get("failed_checks"):
        return "# ✅ No failed checks found.\n"

    report = "# 🚨 Checkov Scan Report\n"
    report += f"_Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_\n\n"

    failed = data["results"]["failed_checks"]
    report += f"## ❌ {len(failed)} Failed Checks\n\n"

    for check in failed:
        report += f"### 🔎 {check.get('check_id')} - {check.get('check_name')}\n"
        report += f"- **Severity**: `{check.get('severity', 'UNKNOWN')}`\n"
        report += f"- **File**: `{check.get('file_path')}`\n"
        report += f"- **Resource**: `{check.get('resource')}`\n"
        report += f"- **Guideline**: {check.get('guideline', 'N/A')}\n\n"

    return report

if __name__ == "__main__":
    os.makedirs("checkov_reports", exist_ok=True)
    markdown = parse_checkov_report("checkov_reports/report.json")
    with open("checkov_reports/report.md", "w") as f:
        f.write(markdown)

    print("[✅] Markdown report generated.")

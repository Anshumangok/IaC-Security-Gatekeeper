import json
import os

def parse_checkov_report(report_path):
    if not os.path.exists(report_path):
        print(f"[ERROR] Report file not found: {report_path}")
        return ""

    with open(report_path, "r") as f:
        data = json.load(f)

    if "results" not in data:
        return "# ✅ No issues found by Checkov.\n"

    output = "# 🚨 Checkov Report\n\n"
    results = data.get("results", {})
    failed_checks = results.get("failed_checks", [])

    if not failed_checks:
        return "# ✅ No failed checks found!\n"

    for check in failed_checks:
        output += f"## ❌ {check.get('check_id')} - {check.get('check_name')}\n"
        output += f"- **Severity**: {check.get('severity', 'UNKNOWN')}\n"
        output += f"- **File**: `{check.get('file_path')}`\n"
        output += f"- **Resource**: `{check.get('resource')}`\n"
        output += f"- **Guideline**: {check.get('guideline') or 'N/A'}\n"
        output += f"- **Description**: {check.get('check_details') or 'No description'}\n\n"

    return output

if __name__ == "__main__":
    input_path = os.getenv("CHECKOV_JSON_PATH", "checkov_reports/report.json")
    markdown = parse_checkov_report(input_path)

    output_path = "checkov_reports/report.md"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        f.write(markdown)

    print(f"[✅] Markdown report generated at: {output_path}")

import json
import os
from datetime import datetime

def parse_json_lines(path):
    content = []
    with open(path, 'r') as f:
        for line in f:
            try:
                data = json.loads(line)
                if isinstance(data, list):
                    content.extend(data)
                else:
                    content.append(data)
            except json.JSONDecodeError:
                continue
    return content

def generate_md(data):
    output = "# 🚨 Checkov Scan Report\n"
    output += f"_Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_\n\n"

    failed_checks = []

    for item in data:
        results = item.get("results", {})
        failed_checks.extend(results.get("failed_checks", []))

    if not failed_checks:
        output += "✅ No failed checks found.\n"
        return output

    output += f"## ❌ {len(failed_checks)} Failed Checks\n\n"
    for check in failed_checks:
        output += f"### 🔎 {check.get('check_id')} - {check.get('check_name')}\n"
        output += f"- **Severity**: `{check.get('severity', 'UNKNOWN')}`\n"
        output += f"- **File**: `{check.get('file_path')}`\n"
        output += f"- **Resource**: `{check.get('resource')}`\n"
        output += f"- **Guideline**: {check.get('guideline', 'N/A')}\n"
        output += f"- **Description**: {check.get('check_details', 'No description')}`\n\n"
    return output

if __name__ == "__main__":
    os.makedirs("checkov_reports", exist_ok=True)
    input_path = "checkov_reports/report.json"
    output_path = "checkov_reports/report.md"

    parsed = parse_json_lines(input_path)
    markdown = generate_md(parsed)

    with open(output_path, "w") as f:
        f.write(markdown)

    print(f"[✅] Markdown report saved to: {output_path}")

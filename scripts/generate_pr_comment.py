import json
from pathlib import Path
from fix_snippets import FIX_SNIPPETS

CHECKOV_JSON = Path("checkov_reports/report.json")
COMMENT_FILE = Path("checkov_reports/pr_comment.md")

def load_checkov_results():
    with open(CHECKOV_JSON) as f:
        data = json.load(f)
    return data["results"].get("failed_checks", [])

def get_fix_snippet(check_id, bucket_name):
    template = FIX_SNIPPETS.get(check_id)
    if not template:
        return "_No fix available._"
    return template.format(bucket_name=bucket_name)

def extract_bucket_name(resource_id):
    parts = resource_id.split(".")
    return parts[-1] if len(parts) >= 2 else "bucket"

def generate_comment(checks):
    lines = ["# \ud83d\udd10 IaC Security Issues Detected", ""]
    if not checks:
        lines.append("\u2705 No security issues found by Checkov!")
    else:
        for check in checks:
            check_id = check.get("check_id", "N/A")
            name = check.get("check_name", "Unknown Check")
            file_path = check.get("file_path", "N/A")
            resource = check.get("resource", "unknown.resource")
            severity = check.get("severity", "UNKNOWN").upper()
            bucket_name = extract_bucket_name(resource)
            fix = get_fix_snippet(check_id, bucket_name)

            lines.append(f"### {name} (`{check_id}`)")
            lines.append(f"- **File:** `{file_path}`")
            lines.append(f"- **Resource:** `{resource}`")
            lines.append(f"- **Severity:** **{severity}**")
            lines.append(f"#### \ud83d\udca1 Suggested Fix:\n{fix}\n\n---\n")

    with open(COMMENT_FILE, "w") as f:
        f.write("\n".join(lines))

if __name__ == "__main__":
    checks = load_checkov_results()
    generate_comment(checks)

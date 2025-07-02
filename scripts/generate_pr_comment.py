import json
import sys
from pathlib import Path
from fix_snippets import FIX_SNIPPETS

CHECKOV_JSON = Path("checkov_reports/report.json")
COMMENT_FILE = Path("checkov_reports/pr_comment.md")

# Define emojis as Unicode escape sequences for better compatibility
EMOJIS = {
    'lock': '\U0001F512',      # 🔒
    'check': '\U00002705',     # ✅  
    'bulb': '\U0001F4A1',      # 💡
    'shield': '\U0001F6E1',    # 🛡️
    'warning': '\U000026A0',   # ⚠️
}

def load_checkov_results():
    """Load Checkov results with proper error handling."""
    try:
        if not CHECKOV_JSON.exists():
            print(f"Checkov report not found at {CHECKOV_JSON}")
            return []
            
        with open(CHECKOV_JSON, encoding='utf-8') as f:
            data = json.load(f)
        
        # Handle different JSON structures
        if "results" in data:
            return data["results"].get("failed_checks", [])
        elif "failed_checks" in data:
            return data.get("failed_checks", [])
        elif isinstance(data, list) and data:
            # Handle array format
            all_failed = []
            for item in data:
                if isinstance(item, dict):
                    if "results" in item:
                        all_failed.extend(item["results"].get("failed_checks", []))
                    elif "failed_checks" in item:
                        all_failed.extend(item.get("failed_checks", []))
            return all_failed
        else:
            return []
    except Exception as e:
        print(f"Error loading Checkov results: {e}")
        return []

def get_fix_snippet(check_id, bucket_name):
    """Get fix snippet for a specific check ID."""
    template = FIX_SNIPPETS.get(check_id)
    if not template:
        return "_No automated fix available for this check._"
    return template.format(bucket_name=bucket_name)

def extract_bucket_name(resource_id):
    """Extract bucket name from resource ID."""
    if not resource_id:
        return "bucket"
    parts = resource_id.split(".")
    return parts[-1] if len(parts) >= 2 else "bucket"

def get_severity_emoji(severity):
    """Get emoji for severity level."""
    severity_map = {
        'CRITICAL': '\U0001F534',  # 🔴
        'HIGH': '\U0001F7E0',      # 🟠
        'MEDIUM': '\U0001F7E1',    # 🟡
        'LOW': '\U0001F535',       # 🔵
        'UNKNOWN': '\U000026AB'    # ⚫
    }
    return severity_map.get(severity.upper(), '\U000026AB')

def generate_comment(checks):
    """Generate PR comment with security findings."""
    try:
        lines = [f"# {EMOJIS['shield']} IaC Security Scan Report", ""]
        
        if not checks:
            lines.append(f"{EMOJIS['check']} **All security checks passed!** No issues detected by Checkov.")
            lines.append("")
            lines.append("Great job maintaining secure infrastructure code!")
        else:
            lines.append(f"{EMOJIS['warning']} **{len(checks)} security issue(s) detected**")
            lines.append("")
            
            # Group by severity
            severity_groups = {}
            for check in checks:
                severity = (check.get("severity") or "UNKNOWN").upper()
                if severity not in severity_groups:
                    severity_groups[severity] = []
                severity_groups[severity].append(check)
            
            # Sort by severity priority
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
            
            for severity in severity_order:
                if severity not in severity_groups:
                    continue
                    
                severity_checks = severity_groups[severity]
                emoji = get_severity_emoji(severity)
                lines.append(f"## {emoji} {severity} Severity ({len(severity_checks)} issue(s))")
                lines.append("")
                
                for check in severity_checks:
                    check_id = check.get("check_id", "N/A")
                    name = check.get("check_name", "Unknown Check")
                    file_path = check.get("file_path", "N/A")
                    resource = check.get("resource", "unknown.resource")
                    bucket_name = extract_bucket_name(resource)
                    fix = get_fix_snippet(check_id, bucket_name)
                    
                    # Get line numbers if available
                    line_range = check.get("file_line_range", [])
                    line_info = f" (lines {line_range[0]}-{line_range[-1]})" if line_range else ""
                    
                    lines.append(f"### {name}")
                    lines.append(f"- **Check ID:** `{check_id}`")
                    lines.append(f"- **File:** `{file_path}`{line_info}")
                    lines.append(f"- **Resource:** `{resource}`")
                    
                    # Add description if available
                    description = check.get("description", "").strip()
                    if description:
                        lines.append(f"- **Description:** {description}")
                    
                    lines.append("")
                    lines.append(f"#### {EMOJIS['bulb']} Suggested Fix:")
                    lines.append(fix)
                    lines.append("")
                    lines.append("---")
                    lines.append("")
        
        # Add footer
        lines.append("---")
        lines.append("*This comment was automatically generated by the IaC Security Gatekeeper*")
        
        # Write to file with proper encoding
        with open(COMMENT_FILE, "w", encoding='utf-8') as f:
            content = "\n".join(lines)
            f.write(content)
            
        print(f"PR comment generated successfully at {COMMENT_FILE}")
        print(f"Comment length: {len(content)} characters")
        
    except Exception as e:
        print(f"Error generating comment: {e}")
        # Create minimal fallback comment
        fallback_lines = [
            "# IaC Security Scan Report",
            "",
            "Security scan completed with some issues processing the results.",
            "Please check the full security report in the workflow artifacts.",
            "",
            "---",
            "*Generated by IaC Security Gatekeeper*"
        ]
        
        with open(COMMENT_FILE, "w", encoding='utf-8') as f:
            f.write("\n".join(fallback_lines))
        print("Fallback comment created")

if __name__ == "__main__":
    try:
        print("Loading Checkov results...")
        checks = load_checkov_results()
        print(f"Found {len(checks)} failed checks")
        
        print("Generating PR comment...")
        generate_comment(checks)
        
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)
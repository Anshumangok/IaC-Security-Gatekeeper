import json
import os
from datetime import datetime
import sys

def parse_checkov_report(json_path):
    """Parse Checkov JSON report and generate markdown"""
    
    # Check if path is a directory (common Checkov issue)
    if os.path.isdir(json_path):
        print(f"❌ Error: {json_path} is a directory, not a file")
        # Try to find JSON files in the directory
        json_files = [f for f in os.listdir(json_path) if f.endswith('.json')]
        if json_files:
            json_path = os.path.join(json_path, json_files[0])
            print(f"🔍 Found JSON file: {json_path}")
        else:
            return generate_error_report(f"Path is a directory with no JSON files: {json_path}")
    
    # Check if file exists
    if not os.path.exists(json_path):
        print(f"❌ Error: {json_path} not found")
        # Try alternative paths
        alternative_paths = [
            "report.json",
            "./report.json", 
            "checkov_reports/checkov_report.json",
            "results.json"
        ]
        for alt_path in alternative_paths:
            if os.path.exists(alt_path):
                print(f"🔍 Found alternative path: {alt_path}")
                json_path = alt_path
                break
        else:
            return generate_error_report(f"JSON report file not found: {json_path}")
    
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            
        if not content:
            print("❌ Error: JSON file is empty")
            return generate_error_report("JSON report file is empty")
            
        # Parse JSON
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            print(f"❌ Error parsing JSON: {e}")
            print("📄 Raw content preview:")
            print(content[:500] + "..." if len(content) > 500 else content)
            return generate_error_report(f"Invalid JSON format: {e}")
        
        # Debug: Print structure
        print("🔍 JSON structure keys:", list(data.keys()) if isinstance(data, dict) else "Not a dict")
        
        # Handle different Checkov output formats
        failed_checks = []
        passed_checks = []
        
        if isinstance(data, dict):
            # New format: results at top level
            if "results" in data:
                results = data["results"]
                failed_checks = results.get("failed_checks", [])
                passed_checks = results.get("passed_checks", [])
            # Alternative format: direct access
            elif "failed_checks" in data:
                failed_checks = data.get("failed_checks", [])
                passed_checks = data.get("passed_checks", [])
            # Check if it's a list format
        elif isinstance(data, list):
            # Sometimes Checkov returns a list
            for item in data:
                if isinstance(item, dict):
                    if "results" in item:
                        failed_checks.extend(item["results"].get("failed_checks", []))
                        passed_checks.extend(item["results"].get("passed_checks", []))
                    elif "failed_checks" in item:
                        failed_checks.extend(item.get("failed_checks", []))
                        passed_checks.extend(item.get("passed_checks", []))
        
        print(f"📊 Found {len(failed_checks)} failed checks and {len(passed_checks)} passed checks")
        
        # Debug: Print first failed check structure if available
        if failed_checks:
            print("🔍 First failed check structure:")
            first_check = failed_checks[0]
            for key, value in first_check.items():
                print(f"  {key}: {type(value)} = {str(value)[:100]}...")
        
        return generate_markdown_report(failed_checks, passed_checks)
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return generate_error_report(f"Unexpected error processing report: {e}")

def generate_error_report(error_message):
    """Generate an error report in markdown format"""
    report = "# ❌ Checkov Scan Report - Error\n\n"
    report += f"_Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_\n\n"
    report += f"**Error**: {error_message}\n\n"
    report += "## Troubleshooting\n\n"
    report += "1. Check if Checkov ran successfully\n"
    report += "2. Verify the JSON output format\n"
    report += "3. Check file permissions and paths\n"
    return report

def get_severity_emoji(severity):
    """Get emoji for severity level"""
    severity_emojis = {
        'CRITICAL': '🔴',
        'HIGH': '🟠',
        'MEDIUM': '🟡',
        'LOW': '🔵',
        'INFO': '⚪',
        'UNKNOWN': '⚫'
    }
    return severity_emojis.get(severity.upper(), '⚫')

def truncate_text(text, max_length=50):
    """Truncate text for table display"""
    if not text or len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."

def extract_filename(file_path):
    """Extract just the filename from full path"""
    if not file_path:
        return "N/A"
    return os.path.basename(file_path)

def generate_markdown_report(failed_checks, passed_checks):
    """Generate the main markdown report with table format"""
    report = "# 🛡️ Checkov IaC Security Scan Report\n\n"
    report += f"_Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_\n\n"
    
    # Summary section
    report += "## 📊 Summary\n\n"
    report += f"- ✅ **Passed Checks**: {len(passed_checks)}\n"
    report += f"- ❌ **Failed Checks**: {len(failed_checks)}\n"
    report += f"- 📝 **Total Checks**: {len(passed_checks) + len(failed_checks)}\n\n"
    
    if len(failed_checks) == 0:
        report += "## 🎉 All Checks Passed!\n\n"
        report += "Your Infrastructure as Code files are compliant with security best practices.\n\n"
        return report
    
    # Failed checks section in table format
    report += f"## ❌ Failed Checks ({len(failed_checks)})\n\n"
    
    # Create table header
    report += "| # | Severity | Check ID | Check Name | File | Resource | Lines |\n"
    report += "|---|----------|----------|------------|------|----------|-------|\n"
    
    # Sort failed checks by severity
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4, 'UNKNOWN': 5}
    
    # Sort checks: first by severity, then by check name
    sorted_checks = sorted(failed_checks, key=lambda x: (
        severity_order.get(str(x.get('severity', 'UNKNOWN')).upper(), 5),
        x.get('check_name', '')
    ))
    
    # Generate table rows
    for i, check in enumerate(sorted_checks, 1):
        severity = str(check.get('severity', 'UNKNOWN')).upper()
        severity_with_emoji = f"{get_severity_emoji(severity)} {severity}"
        
        check_id = check.get('check_id', 'N/A')
        check_name = truncate_text(check.get('check_name', 'Unknown Check'), 40)
        file_path = extract_filename(check.get('file_path', 'N/A'))
        resource = truncate_text(check.get('resource', 'N/A'), 30)
        
        # Handle line numbers
        line_info = "N/A"
        if 'file_line_range' in check and check['file_line_range']:
            line_range = check['file_line_range']
            if isinstance(line_range, list) and len(line_range) >= 2:
                line_info = f"{line_range[0]}-{line_range[1]}"
        
        # Add table row
        report += f"| {i} | {severity_with_emoji} | `{check_id}` | {check_name} | `{file_path}` | {resource} | {line_info} |\n"
    
    # Add severity legend
    report += "\n### 🎯 Severity Legend\n\n"
    report += "| Severity | Description |\n"
    report += "|----------|-------------|\n"
    report += "| 🔴 CRITICAL | Immediate security risk requiring urgent attention |\n"
    report += "| 🟠 HIGH | Significant security vulnerability |\n"
    report += "| 🟡 MEDIUM | Moderate security concern |\n"
    report += "| 🔵 LOW | Minor security improvement |\n"
    report += "| ⚪ INFO | Informational finding |\n"
    report += "| ⚫ UNKNOWN | Severity not specified |\n\n"
    
    # Group and show detailed information by severity
    severity_groups = {}
    for check in failed_checks:
        severity = check.get('severity', 'UNKNOWN')
        if severity is None or severity == '':
            severity = 'UNKNOWN'
        severity = str(severity).upper()
        if severity not in severity_groups:
            severity_groups[severity] = []
        severity_groups[severity].append(check)
    
    report += "## 📝 Detailed Information\n\n"
    
    # Order by severity (CRITICAL, HIGH, MEDIUM, LOW, etc.)
    severity_order_list = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN']
    
    for severity in severity_order_list:
        if severity in severity_groups:
            checks = severity_groups[severity]
            emoji = get_severity_emoji(severity)
            report += f"### {emoji} {severity} Severity Issues ({len(checks)})\n\n"
            
            for i, check in enumerate(checks, 1):
                report += f"#### {i}. {check.get('check_name', 'Unknown Check')}\n\n"
                report += f"- **Check ID**: `{check.get('check_id', 'N/A')}`\n"
                report += f"- **File**: `{check.get('file_path', 'N/A')}`\n"
                report += f"- **Resource**: `{check.get('resource', 'N/A')}`\n"
                
                # Add line numbers if available
                if 'file_line_range' in check and check['file_line_range']:
                    line_range = check['file_line_range']
                    if isinstance(line_range, list) and len(line_range) >= 2:
                        report += f"- **Lines**: {line_range[0]}-{line_range[1]}\n"
                
                # Add description if available
                description = check.get('description', '')
                if description and description.strip():
                    report += f"- **Description**: {description}\n"
                
                # Add guideline if available
                guideline = check.get('guideline', '')
                if guideline and guideline.strip():
                    report += f"- **Guideline**: {guideline}\n"
                
                # Add code block if available
                if 'code_block' in check and check['code_block']:
                    try:
                        if isinstance(check['code_block'], list) and len(check['code_block']) > 0:
                            if isinstance(check['code_block'][0], list) and len(check['code_block'][0]) > 1:
                                code = check['code_block'][0][1]
                                report += f"\n**Code Block:**\n```hcl\n{code}\n```\n"
                    except (IndexError, TypeError):
                        # Skip if code_block format is unexpected
                        pass
                
                report += "\n---\n\n"
    
    # Add remediation tips
    report += "## 🔧 Remediation Tips\n\n"
    report += "1. **Prioritize by severity** - Address CRITICAL and HIGH issues first\n"
    report += "2. **Review each failed check** and understand the security implications\n"
    report += "3. **Apply the recommended fixes** based on the guidelines provided\n"
    report += "4. **Test your changes** in a development environment first\n"
    report += "5. **Re-run Checkov** to verify fixes\n\n"
    
    return report

def main():
    """Main function"""
    # Ensure reports directory exists
    os.makedirs("checkov_reports", exist_ok=True)
    
    json_path = "checkov_reports/report.json"
    output_path = "checkov_reports/report.md"
    
    print(f"🔍 Looking for Checkov JSON report at: {json_path}")
    
    # Generate markdown report
    markdown_content = parse_checkov_report(json_path)
    
    # Write markdown report
    try:
        with open(output_path, "w", encoding='utf-8') as f:
            f.write(markdown_content)
        print(f"✅ Markdown report generated successfully at: {output_path}")
        
        # Print summary to console
        print("\n📄 Report Summary:")
        lines = markdown_content.split('\n')
        for line in lines:
            if line.startswith('- ✅') or line.startswith('- ❌') or line.startswith('- 📝'):
                print(line)
                
    except Exception as e:
        print(f"❌ Error writing markdown report: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
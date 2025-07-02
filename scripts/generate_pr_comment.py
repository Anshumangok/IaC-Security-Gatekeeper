#!/usr/bin/env python3
"""
Debug script to troubleshoot Checkov output issues
"""

import json
import os
from pathlib import Path

def check_checkov_report():
    """Check the Checkov report and provide debugging info."""
    report_path = Path("checkov_reports/report.json")
    
    print("=== Checkov Report Debug ===")
    print(f"Current directory: {os.getcwd()}")
    print(f"Report path: {report_path.absolute()}")
    print(f"Report exists: {report_path.exists()}")
    
    if report_path.exists():
        print(f"Report is file: {report_path.is_file()}")
        print(f"Report is directory: {report_path.is_dir()}")
        
        if report_path.is_file():
            try:
                print(f"File size: {report_path.stat().st_size} bytes")
                
                # Try to read as text first
                with open(report_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    print(f"Content length: {len(content)} characters")
                    print("First 200 characters:")
                    print(repr(content[:200]))
                    
                # Try to parse as JSON
                try:
                    data = json.loads(content)
                    print("✅ Valid JSON structure")
                    print(f"JSON type: {type(data)}")
                    
                    if isinstance(data, dict):
                        print(f"Top-level keys: {list(data.keys())}")
                        
                        if "results" in data:
                            results = data["results"]
                            print(f"Results type: {type(results)}")
                            if isinstance(results, dict):
                                print(f"Results keys: {list(results.keys())}")
                                failed = results.get("failed_checks", [])
                                passed = results.get("passed_checks", [])
                                print(f"Failed checks: {len(failed)}")
                                print(f"Passed checks: {len(passed)}")
                        
                        elif "failed_checks" in data:
                            failed = data.get("failed_checks", [])
                            passed = data.get("passed_checks", [])
                            print(f"Failed checks: {len(failed)}")
                            print(f"Passed checks: {len(passed)}")
                    
                    elif isinstance(data, list):
                        print(f"Array with {len(data)} items")
                        if data:
                            print(f"First item type: {type(data[0])}")
                            if isinstance(data[0], dict):
                                print(f"First item keys: {list(data[0].keys())}")
                    
                except json.JSONDecodeError as e:
                    print(f"❌ Invalid JSON: {e}")
                    print("Attempting to fix JSON structure...")
                    
                    # Try to extract valid JSON from the content
                    lines = content.split('\n')
                    for i, line in enumerate(lines):
                        if line.strip().startswith('{') or line.strip().startswith('['):
                            try:
                                potential_json = '\n'.join(lines[i:])
                                json.loads(potential_json)
                                print(f"Found valid JSON starting at line {i+1}")
                                break
                            except:
                                continue
                    else:
                        print("No valid JSON found in file")
                        
            except Exception as e:
                print(f"Error reading file: {e}")
        
        elif report_path.is_dir():
            print("Report path is a directory. Contents:")
            try:
                for item in report_path.iterdir():
                    print(f"  - {item.name} ({'dir' if item.is_dir() else 'file'})")
            except Exception as e:
                print(f"Error listing directory: {e}")
    else:
        print("Report file does not exist")
        
        # Check if directory exists
        report_dir = report_path.parent
        print(f"Report directory exists: {report_dir.exists()}")
        if report_dir.exists():
            print("Directory contents:")
            try:
                for item in report_dir.iterdir():
                    print(f"  - {item.name} ({'dir' if item.is_dir() else 'file'})")
            except Exception as e:
                print(f"Error listing directory: {e}")

def create_test_report():
    """Create a test report for validation."""
    test_report = {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_21",
                    "check_name": "S3 Bucket has server-side encryption enabled",
                    "file_path": "main.tf",
                    "resource": "aws_s3_bucket.unsecure_bucket",
                    "severity": "HIGH",
                    "description": "S3 bucket should have server-side encryption enabled"
                }
            ],
            "passed_checks": []
        }
    }
    
    report_path = Path("checkov_reports/test_report.json")
    report_path.parent.mkdir(exist_ok=True)
    
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(test_report, f, indent=2)
    
    print(f"✅ Test report created at {report_path}")

if __name__ == "__main__":
    check_checkov_report()
    print("\n" + "="*50 + "\n")
    create_test_report()
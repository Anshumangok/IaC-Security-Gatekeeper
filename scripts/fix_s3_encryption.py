import os
import re
from pathlib import Path

SOURCE_DIR = "terraform"
OUTPUT_DIR = "fix_artifacts"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def has_encryption_block(content, bucket_name):
    return f'aws_s3_bucket_server_side_encryption_configuration' in content and bucket_name in content

def extract_bucket_name(block):
    match = re.search(r'resource\s+"aws_s3_bucket"\s+"(\w+)"', block)
    return match.group(1) if match else "bucket"

def fix_s3_encryption(file_path):
    with open(file_path, 'r') as f:
        content = f.read()

    matches = re.findall(r'resource\s+"aws_s3_bucket"\s+"\w+"\s*{[^}]*}', content, re.DOTALL)
    fixed = content

    for block in matches:
        bucket_name = extract_bucket_name(block)
        if not has_encryption_block(content, bucket_name):
            print(f"🛠️ Adding encryption for bucket: {bucket_name}")
            encryption_block = f'''
resource "aws_s3_bucket_server_side_encryption_configuration" "{bucket_name}_encryption" {{
  bucket = aws_s3_bucket.{bucket_name}.id

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
  }}
}}
'''
            fixed += encryption_block

    # Write to fixed_artifacts
    output_file = Path(OUTPUT_DIR) / Path(file_path).name
    with open(output_file, 'w') as f:
        f.write(fixed)
    print(f"✅ Fixed file saved to: {output_file}")

def scan_and_fix():
    for root, _, files in os.walk(SOURCE_DIR):
        for file in files:
            if file.endswith(".tf"):
                fix_s3_encryption(os.path.join(root, file))

if __name__ == "__main__":
    scan_and_fix()

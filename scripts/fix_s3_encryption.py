# scripts/fix_s3_encryption.py

import os
import re

def has_encryption_block(content):
    return "server_side_encryption_configuration" in content

def inject_encryption_block(tf_path):
    with open(tf_path, 'r') as f:
        content = f.read()

    if not has_encryption_block(content) and 'resource "aws_s3_bucket"' in content:
        print(f"[⚙️] Adding encryption to: {tf_path}")

        # Inject after the closing } of the aws_s3_bucket block
        bucket_match = re.search(r'(resource\s+"aws_s3_bucket"\s+".*?"\s*{.*?})', content, re.DOTALL)
        if bucket_match:
            new_block = f'''
resource "aws_s3_bucket_server_side_encryption_configuration" "sse_config" {{
  bucket = aws_s3_bucket.my_bucket.id

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
  }}
}}
'''
            content += new_block
            with open(tf_path, 'w') as f:
                f.write(content)
            print(f"[✅] Encryption block added in {tf_path}")
        else:
            print(f"[⚠️] No aws_s3_bucket resource found in {tf_path}")
    else:
        print(f"[ℹ️] {tf_path} already has encryption or no S3 bucket.")

def scan_and_fix():
    for root, _, files in os.walk("terraform"):
        for file in files:
            if file.endswith(".tf"):
                inject_encryption_block(os.path.join(root, file))

if __name__ == "__main__":
    scan_and_fix()

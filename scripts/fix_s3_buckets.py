import re
import os

def fix_s3_bucket_acl(tf_path):
    with open(tf_path, "r") as f:
        content = f.read()

    # Replace public ACLs
    fixed = re.sub(r'acl\s*=\s*"(public-read|public-write)"', 'acl = "private"', content)

    # Check if fix was applied
    if fixed != content:
        with open(tf_path, "w") as f:
            f.write(fixed)
        print(f"[✅] Fixed public S3 ACL in {tf_path}")
    else:
        print(f"[ℹ️] No public ACL found in {tf_path}")

def scan_and_fix():
    for root, _, files in os.walk("terraform"):
        for file in files:
            if file.endswith(".tf"):
                fix_s3_bucket_acl(os.path.join(root, file))

if __name__ == "__main__":
    scan_and_fix()

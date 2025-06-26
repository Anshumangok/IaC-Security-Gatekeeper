import os
import re

SOURCE_DIR = "terraform"
OUTPUT_DIR = "fix_artifacts"

PUBLIC_NAME_KEYWORDS = ["public", "cdn", "static", "assets"]
PUBLIC_TAG_KEYS = ["public", "website", "cdn"]
PUBLIC_COMMENT_KEYWORDS = ["for hosting", "for public use", "cdn", "static hosting"]

def has_public_acl(content):
    return re.search(r'acl\s*=\s*"public-read(-write)?"', content)

def get_tags(content):
    match = re.search(r'tags\s*=\s*{([^}]+)}', content, re.DOTALL)
    return match.group(1) if match else ""

def is_intentional_public(bucket_name, tags_block, comment_block):
    name_signal = any(kw in bucket_name.lower() for kw in PUBLIC_NAME_KEYWORDS)
    tag_signal = any(kw in tags_block.lower() for kw in PUBLIC_TAG_KEYS)
    comment_signal = any(kw in comment_block.lower() for kw in PUBLIC_COMMENT_KEYWORDS)
    return name_signal or tag_signal or comment_signal

def extract_comment_near_acl(lines, index):
    for i in range(index - 1, -1, -1):
        line = lines[i].strip()
        if line.startswith("#"):
            return line
        if line:
            break
    return ""

def fix_acl_files():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    summary = []

    for root, _, files in os.walk(SOURCE_DIR):
        for file in files:
            if not file.endswith(".tf"):
                continue

            file_path = os.path.join(root, file)
            with open(file_path, "r") as f:
                lines = f.readlines()

            content = "".join(lines)
            if not has_public_acl(content):
                continue

            fixed_lines = lines[:]
            modified = False
            bucket_name = "unknown"

            for i, line in enumerate(lines):
                if 'resource "aws_s3_bucket"' in line:
                    match = re.search(r'"aws_s3_bucket"\s+"(.*?)"', line)
                    if match:
                        bucket_name = match.group(1)

                if 'acl' in line and 'public' in line:
                    comment = extract_comment_near_acl(lines, i)
                    tags = get_tags(content)

                    if not is_intentional_public(bucket_name, tags, comment):
                        fixed_lines[i] = '  acl = "private"\n'
                        modified = True
                        summary.append(f"✅ Fixed: {bucket_name} in {file}")
                    else:
                        summary.append(f"🟡 Skipped (intentional): {bucket_name} in {file}")

            if modified:
                output_path = os.path.join(OUTPUT_DIR, file)
                with open(output_path, "w") as f:
                    f.writelines(fixed_lines)

    with open(os.path.join(OUTPUT_DIR, "s3_acl_fix_report.md"), "w") as report:
        report.write("# 🛠️ S3 ACL Fix Summary\n\n")
        for entry in summary:
            report.write(f"- {entry}\n")

    print(f"[✅] Fix complete. {len(summary)} entries written to fix_artifacts/")

if __name__ == "__main__":
    fix_acl_files()
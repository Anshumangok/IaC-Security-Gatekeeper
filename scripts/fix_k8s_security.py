# scripts/fix_k8s_security.py

import os
import yaml

def inject_security_context_to_container(container):
    if "securityContext" not in container:
        container["securityContext"] = {
            "runAsNonRoot": True,
            "allowPrivilegeEscalation": False,
            "capabilities": {
                "drop": ["ALL"]
            }
        }
        return True
    return False

def inject_pod_level_security_context(doc):
    if "spec" in doc and "securityContext" not in doc["spec"]:
        doc["spec"]["securityContext"] = {
            "runAsNonRoot": True,
            "fsGroup": 2000
        }
        return True
    return False

def fix_k8s_yaml(file_path):
    modified = False
    with open(file_path, "r") as f:
        try:
            docs = list(yaml.safe_load_all(f))
        except yaml.YAMLError as e:
            print(f"[❌] YAML parsing error in {file_path}: {e}")
            return

    for doc in docs:
        if not isinstance(doc, dict) or "kind" not in doc or "spec" not in doc:
            continue
        containers = doc.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        for container in containers:
            modified |= inject_security_context_to_container(container)

        modified |= inject_pod_level_security_context(doc.get("spec", {}).get("template", {}) or doc["spec"])

    if modified:
        with open(file_path, "w") as f:
            yaml.dump_all(docs, f, sort_keys=False)
        print(f"[✅] Security context injected in {file_path}")
    else:
        print(f"[ℹ️] No changes needed in {file_path}")

def scan_and_fix_k8s():
    for root, _, files in os.walk("k8s"):
        for file in files:
            if file.endswith((".yaml", ".yml")):
                fix_k8s_yaml(os.path.join(root, file))

if __name__ == "__main__":
    scan_and_fix_k8s()

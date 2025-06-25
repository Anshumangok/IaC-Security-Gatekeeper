# scripts/fix_k8s_security.py

import os
import yaml
import json
from datetime import datetime
from typing import Dict, List, Any

def log_message(message: str, level: str = "INFO"):
    """Log messages with timestamp and level"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")

def inject_security_context_to_container(container: Dict[str, Any]) -> bool:
    """Inject security context into a container if missing"""
    if "securityContext" not in container:
        container["securityContext"] = {
            "runAsNonRoot": True,
            "runAsUser": 1000,
            "runAsGroup": 1000,
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "capabilities": {
                "drop": ["ALL"]
            }
        }
        log_message(f"Added securityContext to container: {container.get('name', 'unnamed')}", "INFO")
        return True
    else:
        # Check if existing security context is secure enough
        sc = container["securityContext"]
        improvements = []
        
        if not sc.get("runAsNonRoot"):
            sc["runAsNonRoot"] = True
            improvements.append("runAsNonRoot")
        
        if not sc.get("allowPrivilegeEscalation", True) == False:
            sc["allowPrivilegeEscalation"] = False
            improvements.append("allowPrivilegeEscalation")
        
        if "capabilities" not in sc or "drop" not in sc.get("capabilities", {}):
            if "capabilities" not in sc:
                sc["capabilities"] = {}
            sc["capabilities"]["drop"] = ["ALL"]
            improvements.append("capabilities.drop")
        
        if improvements:
            log_message(f"Enhanced securityContext for {container.get('name', 'unnamed')}: {', '.join(improvements)}", "INFO")
            return True
    
    return False

def inject_pod_level_security_context(pod_spec: Dict[str, Any]) -> bool:
    """Inject pod-level security context if missing"""
    if "securityContext" not in pod_spec:
        pod_spec["securityContext"] = {
            "runAsNonRoot": True,
            "runAsUser": 1000,
            "runAsGroup": 1000,
            "fsGroup": 2000,
            "fsGroupChangePolicy": "OnRootMismatch",
            "seccompProfile": {
                "type": "RuntimeDefault"
            }
        }
        log_message("Added pod-level securityContext", "INFO")
        return True
    else:
        # Enhance existing pod security context
        sc = pod_spec["securityContext"]
        improvements = []
        
        if not sc.get("runAsNonRoot"):
            sc["runAsNonRoot"] = True
            improvements.append("runAsNonRoot")
        
        if "fsGroup" not in sc:
            sc["fsGroup"] = 2000
            improvements.append("fsGroup")
        
        if "seccompProfile" not in sc:
            sc["seccompProfile"] = {"type": "RuntimeDefault"}
            improvements.append("seccompProfile")
        
        if improvements:
            log_message(f"Enhanced pod securityContext: {', '.join(improvements)}", "INFO")
            return True
    
    return False

def add_network_policy_if_missing(doc: Dict[str, Any], namespace: str = "default") -> Dict[str, Any]:
    """Generate a basic network policy for the deployment"""
    app_name = doc.get("metadata", {}).get("name", "app")
    
    network_policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": f"{app_name}-network-policy",
            "namespace": namespace
        },
        "spec": {
            "podSelector": {
                "matchLabels": {
                    "app": app_name
                }
            },
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [
                {
                    "from": [
                        {
                            "podSelector": {
                                "matchLabels": {
                                    "role": "frontend"
                                }
                            }
                        }
                    ],
                    "ports": [
                        {
                            "protocol": "TCP",
                            "port": 8080
                        }
                    ]
                }
            ],
            "egress": [
                {
                    "to": [],
                    "ports": [
                        {
                            "protocol": "TCP",
                            "port": 53
                        },
                        {
                            "protocol": "UDP", 
                            "port": 53
                        }
                    ]
                }
            ]
        }
    }
    
    return network_policy

def fix_k8s_yaml(file_path: str) -> bool:
    """Fix security issues in a Kubernetes YAML file"""
    try:
        with open(file_path, "r") as f:
            try:
                docs = list(yaml.safe_load_all(f))
            except yaml.YAMLError as e:
                log_message(f"YAML parsing error in {file_path}: {e}", "ERROR")
                return False

        modified = False
        new_docs = []
        network_policies_to_add = []

        for doc in docs:
            if not isinstance(doc, dict) or not doc or "kind" not in doc:
                new_docs.append(doc)
                continue
            
            kind = doc.get("kind")
            doc_modified = False
            
            # Handle Deployments, StatefulSets, DaemonSets
            if kind in ["Deployment", "StatefulSet", "DaemonSet"]:
                pod_spec = doc.get("spec", {}).get("template", {}).get("spec", {})
                
                if pod_spec:
                    # Fix pod-level security context
                    if inject_pod_level_security_context(pod_spec):
                        doc_modified = True
                    
                    # Fix container security contexts
                    containers = pod_spec.get("containers", [])
                    for container in containers:
                        if inject_security_context_to_container(container):
                            doc_modified = True
                    
                    # Fix init containers too
                    init_containers = pod_spec.get("initContainers", [])
                    for container in init_containers:
                        if inject_security_context_to_container(container):
                            doc_modified = True
                    
                    # Add resource limits if missing
                    for container in containers + init_containers:
                        if "resources" not in container:
                            container["resources"] = {
                                "limits": {
                                    "memory": "512Mi",
                                    "cpu": "500m"
                                },
                                "requests": {
                                    "memory": "256Mi", 
                                    "cpu": "250m"
                                }
                            }
                            log_message(f"Added resource limits to container: {container.get('name', 'unnamed')}", "INFO")
                            doc_modified = True
                    
                    # Generate network policy
                    namespace = doc.get("metadata", {}).get("namespace", "default")
                    network_policy = add_network_policy_if_missing(doc, namespace)
                    network_policies_to_add.append(network_policy)
            
            # Handle standalone Pods
            elif kind == "Pod":
                pod_spec = doc.get("spec", {})
                
                if inject_pod_level_security_context(pod_spec):
                    doc_modified = True
                
                containers = pod_spec.get("containers", [])
                for container in containers:
                    if inject_security_context_to_container(container):
                        doc_modified = True
            
            # Handle CronJobs
            elif kind == "CronJob":
                pod_spec = doc.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})
                
                if pod_spec:
                    if inject_pod_level_security_context(pod_spec):
                        doc_modified = True
                    
                    containers = pod_spec.get("containers", [])
                    for container in containers:
                        if inject_security_context_to_container(container):
                            doc_modified = True
            
            if doc_modified:
                modified = True
                log_message(f"Modified {kind}: {doc.get('metadata', {}).get('name', 'unnamed')}", "INFO")
            
            new_docs.append(doc)
        
        # Add network policies
        new_docs.extend(network_policies_to_add)
        if network_policies_to_add:
            log_message(f"Added {len(network_policies_to_add)} NetworkPolicy resources", "INFO")
            modified = True

        # Write back if modified
        if modified:
            with open(file_path, "w") as f:
                yaml.dump_all(new_docs, f, default_flow_style=False, sort_keys=False)
            log_message(f"✅ Security enhancements applied to {file_path}", "SUCCESS")
            return True
        else:
            log_message(f"ℹ️ No changes needed in {file_path}", "INFO")
            return False
            
    except Exception as e:
        log_message(f"Error processing {file_path}: {str(e)}", "ERROR")
        return False

def scan_and_fix_k8s() -> bool:
    """Scan for Kubernetes YAML files and fix security issues"""
    log_message("Starting Kubernetes security remediation scan", "INFO")
    
    fixed_files = []
    total_files = 0
    
    # Scan common Kubernetes directories
    search_paths = ["k8s", "kubernetes", "kube", "manifests", "deploy", "deployment", "."]
    
    for search_path in search_paths:
        if not os.path.exists(search_path):
            continue
            
        log_message(f"Scanning {search_path} for Kubernetes YAML files", "INFO")
        
        for root, dirs, files in os.walk(search_path):
            # Skip hidden directories and common exclusions
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__']]
            
            for file in files:
                if file.endswith((".yaml", ".yml")):
                    total_files += 1
                    file_path = os.path.join(root, file)
                    
                    # Quick check if file contains Kubernetes resources
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            if any(kind in content for kind in ['kind: Deployment', 'kind: Pod', 'kind: StatefulSet', 'kind: DaemonSet', 'kind: CronJob']):
                                if fix_k8s_yaml(file_path):
                                    fixed_files.append(file_path)
                    except Exception as e:
                        log_message(f"Error reading {file_path}: {str(e)}", "ERROR")
    
    # Generate summary report
    log_message("=" * 50, "INFO")
    log_message("KUBERNETES SECURITY REMEDIATION SUMMARY", "INFO")
    log_message("=" * 50, "INFO")
    log_message(f"Total YAML files scanned: {total_files}", "INFO")
    log_message(f"Files with security enhancements: {len(fixed_files)}", "INFO")
    
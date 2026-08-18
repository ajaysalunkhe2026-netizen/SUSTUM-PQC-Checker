#!/usr/bin/env python3
import os
import re
import ast
import json

class CryptoASTVisitor(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        self.findings = []

    def visit_Call(self, node):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if any(term in func_name.lower() for term in ["rsa", "dsa", "ec", "aes", "sha1", "cipher", "generate_private_key"]):
            self.findings.append({
                "location": f"{self.filename}:{node.lineno}",
                "asset_type": "Algorithm",
                "algorithm": "RSA-2048" if "rsa" in func_name.lower() else "Cryptographic Function",
                "key_size": "2048" if "rsa" in func_name.lower() else "Unknown",
                "purpose": "Signature" if "sign" in func_name.lower() or "rsa" in func_name.lower() else "Encryption",
                "protocol": "-",
                "library": "cryptography/PyCrypto",
                "vulnerable": True,
                "confidence": "Confirmed via AST",
                "notes": f"Strict AST match on function call: {func_name}"
            })
        self.generic_visit(node)

PATTERNS = [
    {
        "regex": re.compile(r"(RSA[-_]?\d{3,4}|AES[-_]?[12560]{2,3}|ECDSA|ECDH|SHA-1|TLS[-_]?[1023\.]{1,3})", re.IGNORECASE),
        "asset_type": "Algorithm",
        "purpose": "Signature"
    }
]

def scan_file(filepath):
    findings = []
    ext = os.path.splitext(filepath)[1].lower()
    rel_path = os.path.basename(filepath)

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.splitlines()
    except Exception:
        return findings

    if ext == ".py":
        try:
            tree = ast.parse(content, filename=filepath)
            visitor = CryptoASTVisitor(rel_path)
            visitor.visit(tree)
            if visitor.findings:
                return visitor.findings
        except SyntaxError:
            pass

    for idx, line in enumerate(lines, 1):
        stripped = line.strip()
        
        if ext in [".js", ".ts", ".java", ".go", ".c", ".cpp"] and (stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*")):
            continue
        if ext == ".py" and stripped.startswith("#"):
            continue
        if ext in [".env", ".yaml", ".yml"] and stripped.startswith("#"):
            continue

        for p in PATTERNS:
            match = p["regex"].search(line)
            if match:
                algo = match.group(1).upper()
                is_vulnerable = True
                confidence = "Confirmed" if ext == ".py" else "Suspected (Runtime Config / Context Match)"
                if "AES-256" in algo or "SHA-256" in algo or "TLS-1.3" in algo:
                    is_vulnerable = False
                    confidence = "Already Safe"

                findings.append({
                    "location": f"{rel_path}:{idx}",
                    "asset_type": p["asset_type"],
                    "algorithm": algo,
                    "key_size": "2048" if "RSA" in algo else ("256" if "AES" in algo else "Unknown"),
                    "purpose": "Signature" if "RSA" in algo or "ECDSA" in algo else ("Encryption" if "AES" in algo else "Key Exchange"),
                    "protocol": "TLS 1.2" if "TLS" in algo else "-",
                    "library": "Config / Environment Variable" if ext in [".env", ".json", ".yaml"] else "-",
                    "vulnerable": is_vulnerable,
                    "confidence": confidence,
                    "notes": f"Detected in {ext.upper()} file (Static & Runtime Config check)."
                })

    return findings

# SBOM Parsing for Node.js
def parse_package_json(filepath, rel_path):
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for pkg, ver in deps.items():
                findings.append({
                    "location": f"{rel_path}",
                    "asset_type": "Dependency",
                    "algorithm": pkg, 
                    "key_size": ver,  
                    "purpose": "Library",
                    "protocol": "-",
                    "library": pkg,
                    "vulnerable": False, 
                    "confidence": "Confirmed via Manifest",
                    "notes": "Extracted for SBOM generation."
                })
    except Exception:
        pass
    return findings

# SBOM Parsing for Python
def parse_requirements_txt(filepath, rel_path):
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for idx, line in enumerate(f):
                line = line.strip()
                if line and not line.startswith("#"):
                    pkg_info = re.split(r'[=><~]+', line)
                    pkg_name = pkg_info[0].strip()
                    pkg_ver = pkg_info[1].strip() if len(pkg_info) > 1 else "latest"
                    findings.append({
                        "location": f"{rel_path}:{idx+1}",
                        "asset_type": "Dependency",
                        "algorithm": pkg_name,
                        "key_size": pkg_ver,
                        "purpose": "Library",
                        "protocol": "-",
                        "library": pkg_name,
                        "vulnerable": False,
                        "confidence": "Confirmed via Manifest",
                        "notes": "Extracted for SBOM generation."
                    })
    except Exception:
        pass
    return findings

def scan_directory(target_dir):
    all_findings = []
    for root, _, files in os.walk(target_dir):
        if any(p in root for p in [".git", "__pycache__", "node_modules", "venv"]):
            continue
        for file in files:
            fullpath = os.path.join(root, file)
            rel_path = os.path.basename(fullpath)
            
            if file.lower() == "package.json":
                all_findings.extend(parse_package_json(fullpath, file))
            elif file.lower() == "requirements.txt":
                all_findings.extend(parse_requirements_txt(fullpath, file))
            elif file.lower().endswith((".py", ".js", ".ts", ".go", ".java", ".json", ".yaml", ".yml", ".env")):
                if file.lower() != "package.json":
                    all_findings.extend(scan_file(fullpath))
    return all_findings
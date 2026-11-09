#!/usr/bin/env python3
"""Conservative source and dependency inventory for a PQC migration review.

This is static analysis, not runtime cryptographic discovery. Findings are evidence
records and should be reviewed before migration decisions are made.
"""
import ast
import json
import os
import re

SKIP_DIRS = {".git", "__pycache__", "node_modules", "venv", ".venv", "dist", "build"}
SOURCE_EXTENSIONS = {".py", ".js", ".ts", ".java", ".go", ".c", ".cpp", ".json", ".yaml", ".yml", ".env"}
TEXT_PATTERNS = [
    (re.compile(r"\bRSA(?:[-_ ]?(?:1024|2048|3072|4096))?\b", re.I), "RSA", "Signature / key transport", True),
    (re.compile(r"\bECDSA\b", re.I), "ECDSA", "Signature", True),
    (re.compile(r"\bECDH\b", re.I), "ECDH", "Key establishment", True),
    (re.compile(r"\b(?:secp256r1|prime256v1|P-256|P-384)\b", re.I), "Elliptic-curve parameter", "Key establishment / signature", True),
    (re.compile(r"\bDSA\b", re.I), "DSA", "Signature", True),
    (re.compile(r"\bSHA-1\b", re.I), "SHA-1", "Hash", False),
    (re.compile(r"\bTLS[-_ ]?1[.]2\b", re.I), "TLS 1.2", "Protocol configuration", False),
    (re.compile(r"\b(?:ML-KEM|ML-DSA|SLH-DSA)\b", re.I), "PQC algorithm reference", "PQC reference", False),
]
PY_CALLS = {
    "generate_private_key": ("Asymmetric key generation call", "Unknown", "Potential asymmetric key generation"),
    "generate": ("Cryptographic key generation call", "Unknown", "Potential cryptographic key generation"),
    "sign": ("Signature operation", "Unknown", "Signature operation; algorithm depends on key/provider"),
    "verify": ("Signature verification operation", "Unknown", "Signature verification; algorithm depends on key/provider"),
    "exchange": ("Key agreement operation", "Unknown", "Key agreement; algorithm depends on key/provider"),
}
DEPENDENCY_FILES = {"requirements.txt", "pyproject.toml", "Pipfile", "package.json", "go.mod"}


def _finding(location, algorithm, purpose, confidence, evidence, vulnerable=None,
             asset_type="Algorithm", library="-", version="unknown"):
    return {
        "location": location, "asset_type": asset_type, "algorithm": algorithm,
        "key_size": "Unknown", "purpose": purpose, "protocol": "-",
        "library": library, "version": version, "vulnerable": vulnerable,
        "confidence": confidence, "evidence": evidence,
        "notes": "Static indicator only; validate actual runtime use and configuration."
    }


def _dotted_name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


class CryptoASTVisitor(ast.NodeVisitor):
    """Recognize crypto-related Python API calls without classifying every call as RSA."""
    def __init__(self, filename):
        self.filename = filename
        self.findings = []
        self.crypto_imports = set()
        self.aliases = {}

    def visit_Import(self, node):
        for alias in node.names:
            if any(x in alias.name.lower() for x in ("cryptography", "crypto", "nacl", "oqs")):
                local_name = alias.asname or alias.name.split(".")[0]
                self.crypto_imports.add(local_name)
                self.aliases[local_name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ""
        if any(x in module.lower() for x in ("cryptography", "crypto", "nacl", "oqs")):
            for alias in node.names:
                local_name = alias.asname or alias.name
                self.crypto_imports.add(local_name)
                self.aliases[local_name] = module + "." + alias.name
        self.generic_visit(node)

    def visit_Call(self, node):
        name = _dotted_name(node.func)
        parts = name.split(".")
        if parts and parts[0] in self.aliases:
            name = self.aliases[parts[0]] + ("." + ".".join(parts[1:]) if len(parts) > 1 else "")
        low = name.lower()
        if any(token in low for token in ("rsa.generate_private_key", "ec.generate_private_key",
                                          "dsa.generate_private_key", "dh.generate_parameters")):
            algorithm = name.split(".")[-2].upper()
            if algorithm == "EC":
                algorithm = "Elliptic Curve"
            purpose = "Signature / key establishment" if algorithm in {"RSA", "EC", "DSA"} else "Key establishment"
            self.findings.append(_finding(
                f"{self.filename}:{node.lineno}", algorithm, purpose,
                "High-confidence API call", name, True
            ))
        elif any(token in low for token in ("mlkem", "mldsa", "slhdsa", "kyber", "dilithium")):
            self.findings.append(_finding(
                f"{self.filename}:{node.lineno}", "PQC API reference", "PQC operation",
                "High-confidence API call", name, False
            ))
        elif any(token in low for token in ("sign", "verify", "exchange")) and self.crypto_imports:
            self.findings.append(_finding(
                f"{self.filename}:{node.lineno}", "Cryptographic operation", PY_CALLS.get(name.split(".")[-1], ("", "", ""))[2],
                "Contextual API call", name, None
            ))
        self.generic_visit(node)


def scan_file(filepath, relative_path=None):
    findings = []
    rel_path = relative_path or os.path.basename(filepath)
    ext = os.path.splitext(filepath)[1].lower()
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as handle:
            content = handle.read()
    except (OSError, UnicodeError):
        return findings

    if ext == ".py":
        try:
            tree = ast.parse(content, filename=rel_path)
            visitor = CryptoASTVisitor(rel_path)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except SyntaxError as exc:
            findings.append(_finding(f"{rel_path}:{exc.lineno or 1}", "Python parse error",
                                     "Scanner limitation", "Parse error", str(exc), None,
                                     asset_type="Scanner diagnostic"))
        # AST findings are more precise; text scan still catches literals/config references.
    for line_no, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "/*", "*")):
            continue
        for pattern, algorithm, purpose, vulnerable in TEXT_PATTERNS:
            if pattern.search(line):
                findings.append(_finding(
                    f"{rel_path}:{line_no}", algorithm, purpose,
                    "Textual indicator", line.strip()[:240], vulnerable
                ))
    return findings


def _dependency(name, version, location):
    return _finding(location, name, "Dependency inventory", "Manifest entry",
                    "Declared in dependency manifest; crypto usage not established.",
                    None, asset_type="Dependency", library=name, version=version)


def parse_package_json(filepath, rel_path):
    try:
        with open(filepath, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return []
    rows = []
    for group in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, version in (data.get(group) or {}).items():
            rows.append(_dependency(name, str(version), rel_path))
    return rows


def parse_requirements_txt(filepath, rel_path):
    rows = []
    try:
        with open(filepath, encoding="utf-8", errors="replace") as handle:
            for line_no, raw in enumerate(handle, 1):
                line = raw.split("#", 1)[0].strip()
                if not line or line.startswith(("-e ", "--")):
                    continue
                match = re.match(r"([A-Za-z0-9_.-]+)\s*(?:\[[^]]+\])?\s*(.*)", line)
                if match:
                    rows.append(_dependency(match.group(1), match.group(2).strip() or "unspecified",
                                             f"{rel_path}:{line_no}"))
    except OSError:
        pass
    return rows


def scan_directory(target_dir):
    all_findings = []
    root_abs = os.path.abspath(target_dir)
    for current, dirs, files in os.walk(root_abs):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in files:
            fullpath = os.path.join(current, filename)
            rel_path = os.path.relpath(fullpath, root_abs).replace(os.sep, "/")
            lower = filename.lower()
            if lower == "package.json":
                all_findings.extend(parse_package_json(fullpath, rel_path))
            elif lower == "requirements.txt":
                all_findings.extend(parse_requirements_txt(fullpath, rel_path))
            elif lower.endswith(tuple(SOURCE_EXTENSIONS)):
                all_findings.extend(scan_file(fullpath, rel_path))
    return all_findings

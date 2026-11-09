#!/usr/bin/env python3
"""Evidence-oriented static crypto inventory for supported source languages.

This is heuristic static analysis, not runtime discovery or proof of reachability.
Every result should be reviewed against the actual application and build context.
"""
import ast
import io
import json
import os
import re
import tokenize

SKIP_DIRS = {".git", "__pycache__", "node_modules", "venv", ".venv", "dist", "build", "target"}
SOURCE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".json", ".yaml", ".yml", ".env", ".properties"}
DEPENDENCY_FILES = {"requirements.txt", "pyproject.toml", "Pipfile", "package.json", "go.mod"}

# API-specific patterns are intentionally more conservative than keyword matching.
# Each tuple: regex, algorithm, purpose, quantum-vulnerable indicator, confidence.
LANGUAGE_PATTERNS = {
    ".java": [
        (r'KeyPairGenerator\s*\.getInstance\s*\(\s*["\']RSA["\']', "RSA", "Key generation", True, "High-confidence API call"),
        (r'Signature\s*\.getInstance\s*\(\s*["\'][^"\']*RSA', "RSA", "Signature", True, "High-confidence API call"),
        (r'Cipher\s*\.getInstance\s*\(\s*["\'][^"\']*RSA', "RSA", "Encryption / key transport", True, "High-confidence API call"),
        (r'KeyAgreement\s*\.getInstance\s*\(\s*["\']ECDH["\']', "ECDH", "Key establishment", True, "High-confidence API call"),
        (r'Signature\s*\.getInstance\s*\(\s*["\'][^"\']*ECDSA', "ECDSA", "Signature", True, "High-confidence API call"),
        (r'MessageDigest\s*\.getInstance\s*\(\s*["\']SHA-?1["\']', "SHA-1", "Hash", False, "High-confidence API call"),
        (r'MessageDigest\s*\.getInstance\s*\(\s*["\']SHA-?256["\']', "SHA-256", "Hash", False, "High-confidence API call"),
    ],
    ".js": [
        (r'generateKeyPair(?:Sync)?\s*\(\s*["\']rsa["\']', "RSA", "Key generation", True, "High-confidence API call"),
        (r'createSign\s*\(', "Signature operation", "Signature", None, "Contextual API call"),
        (r'createVerify\s*\(', "Signature operation", "Signature verification", None, "Contextual API call"),
        (r'createECDH\s*\(', "ECDH", "Key establishment", True, "High-confidence API call"),
        (r'generateKey\s*\(\s*\{\s*name\s*:\s*["\']RSA', "RSA", "Key generation", True, "High-confidence WebCrypto API"),
        (r'generateKey\s*\(\s*\{\s*name\s*:\s*["\']ECDSA', "ECDSA", "Key generation / signature", True, "High-confidence WebCrypto API"),
        (r'generateKey\s*\(\s*\{\s*name\s*:\s*["\']ECDH', "ECDH", "Key establishment", True, "High-confidence WebCrypto API"),
    ],
    ".ts": [],
    ".go": [
        (r'\brsa\s*\.\s*GenerateKey\s*\(', "RSA", "Key generation", True, "High-confidence API call"),
        (r'\brsa\s*\.\s*(?:SignPSS|SignPKCS1v15|VerifyPSS|VerifyPKCS1v15)\s*\(', "RSA", "Signature", True, "High-confidence API call"),
        (r'\becdsa\s*\.\s*GenerateKey\s*\(', "ECDSA", "Key generation / signature", True, "High-confidence API call"),
        (r'\becdh\s*\.\s*X(?:25519|448)\s*\(', "ECDH", "Key establishment", True, "High-confidence API call"),
        (r'\belliptic\s*\.\s*P(?:224|256|384|521)\s*\(', "Elliptic-curve parameter", "Key establishment / signature", True, "High-confidence API call"),
        (r'\bsha1\s*\.\s*New\s*\(', "SHA-1", "Hash", False, "High-confidence API call"),
        (r'\bsha256\s*\.\s*New\s*\(', "SHA-256", "Hash", False, "High-confidence API call"),
    ],
    ".c": [
        (r'\bRSA_generate_key_ex\s*\(', "RSA", "Key generation", True, "High-confidence OpenSSL API"),
        (r'\bEVP_PKEY_RSA\b', "RSA", "Asymmetric key algorithm reference", True, "OpenSSL algorithm reference"),
        (r'\bEVP_PKEY_EC\b|\bEC_KEY_new_by_curve_name\s*\(', "Elliptic Curve", "Key generation / signature", True, "High-confidence OpenSSL API"),
        (r'\bEVP_PKEY_X25519\b', "ECDH", "Key establishment", True, "OpenSSL algorithm reference"),
        (r'\bEVP_DigestSignInit\s*\(', "Signature operation", "Signature", None, "OpenSSL API; algorithm depends on key"),
        (r'\bEVP_DigestVerifyInit\s*\(', "Signature operation", "Signature verification", None, "OpenSSL API; algorithm depends on key"),
        (r'\bEVP_sha1\s*\(', "SHA-1", "Hash", False, "High-confidence OpenSSL API"),
        (r'\bEVP_sha256\s*\(', "SHA-256", "Hash", False, "High-confidence OpenSSL API"),
    ],
    ".cpp": [],
    ".cc": [],
    ".cxx": [],
    ".h": [],
    ".hpp": [],
    ".hh": [],
}
LANGUAGE_PATTERNS[".ts"] = LANGUAGE_PATTERNS[".js"]
for _ext in (".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh"):
    LANGUAGE_PATTERNS[_ext] = LANGUAGE_PATTERNS[".c"]

TEXT_PATTERNS = [
    (re.compile(r"\bRSA(?:[-_ ]?(?:1024|2048|3072|4096))?\b", re.I), "RSA", "Algorithm reference", True),
    (re.compile(r"\bECDSA\b", re.I), "ECDSA", "Signature", True),
    (re.compile(r"\bECDH\b", re.I), "ECDH", "Key establishment", True),
    (re.compile(r"\b(?:secp256r1|prime256v1|P-256|P-384)\b", re.I), "Elliptic-curve parameter", "Key establishment / signature", True),
    (re.compile(r"\bDSA\b", re.I), "DSA", "Signature", True),
    (re.compile(r"\bSHA-?1\b", re.I), "SHA-1", "Hash", False),
    (re.compile(r"\bTLS[-_ ]?1[.]2\b", re.I), "TLS 1.2", "Protocol configuration", False),
    (re.compile(r"\b(?:ML-KEM|ML-DSA|SLH-DSA|Kyber|Dilithium)\b", re.I), "PQC algorithm reference", "PQC reference", False),
]
PY_CALLS = {
    "generate_private_key": "Potential asymmetric key generation",
    "sign": "Signature operation; algorithm depends on key/provider",
    "verify": "Signature verification; algorithm depends on key/provider",
    "exchange": "Key agreement; algorithm depends on key/provider",
}


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
    def __init__(self, filename):
        self.filename = filename
        self.findings = []
        self.aliases = {}

    def visit_Import(self, node):
        for alias in node.names:
            if any(x in alias.name.lower() for x in ("cryptography", "crypto", "nacl", "oqs")):
                self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ""
        if any(x in module.lower() for x in ("cryptography", "crypto", "nacl", "oqs")):
            for alias in node.names:
                self.aliases[alias.asname or alias.name] = module + "." + alias.name
        self.generic_visit(node)

    def visit_Call(self, node):
        name = _dotted_name(node.func)
        parts = name.split(".")
        if parts and parts[0] in self.aliases:
            name = self.aliases[parts[0]] + ("." + ".".join(parts[1:]) if len(parts) > 1 else "")
        low = name.lower()
        for marker, algorithm, purpose in (
            ("rsa.generate_private_key", "RSA", "Key generation"),
            ("ec.generate_private_key", "Elliptic Curve", "Key generation"),
            ("dsa.generate_private_key", "DSA", "Key generation"),
            ("dh.generate_parameters", "Diffie-Hellman", "Key establishment"),
        ):
            if marker in low:
                self.findings.append(_finding(f"{self.filename}:{node.lineno}", algorithm, purpose,
                    "High-confidence API call", name, True))
                break
        else:
            if any(token in low for token in ("mlkem", "mldsa", "slhdsa", "kyber", "dilithium")):
                self.findings.append(_finding(f"{self.filename}:{node.lineno}", "PQC API reference",
                    "PQC operation", "High-confidence API reference", name, False))
            elif name.split(".")[-1].lower() in {"sign", "verify", "exchange"} and self.aliases:
                operation = name.split(".")[-1].lower()
                self.findings.append(_finding(f"{self.filename}:{node.lineno}", "Cryptographic operation",
                    PY_CALLS[operation], "Contextual API call", name, None))
        self.generic_visit(node)


def _strip_line_comment(line, ext):
    """Remove obvious full-line comments without damaging string literals."""
    stripped = line.lstrip()
    if ext in {".py", ".yaml", ".yml", ".sh"} and stripped.startswith("#"):
        return ""
    if ext not in {".py", ".yaml", ".yml", ".sh"} and stripped.startswith(("//", "/*", "*", "*/")):
        return ""
    return line


def _scan_language_lines(content, rel_path, ext):
    findings = []
    patterns = LANGUAGE_PATTERNS.get(ext, [])
    for line_no, raw_line in enumerate(content.splitlines(), 1):
        line = _strip_line_comment(raw_line, ext)
        if not line.strip():
            continue
        for pattern, algorithm, purpose, vulnerable, confidence in patterns:
            match = re.search(pattern, line, re.I)
            if match:
                findings.append(_finding(f"{rel_path}:{line_no}", algorithm, purpose,
                    confidence, match.group(0)[:240], vulnerable))
        # Detect standard PQC identifiers in source/config even when wrapped by a provider.
        pqc = re.search(r"\b(ML-KEM(?:-512|-768|-1024)?|ML-DSA(?:-44|-65|-87)?|SLH-DSA(?:-[A-Z0-9-]+)?)\b", line, re.I)
        if pqc:
            findings.append(_finding(f"{rel_path}:{line_no}", "PQC algorithm reference",
                "PQC reference", "Textual indicator", pqc.group(0), False))
    return findings


def _mask_python_strings_and_comments(content):
    lines = content.splitlines(keepends=True)
    try:
        for token in tokenize.generate_tokens(io.StringIO(content).readline):
            if token.type not in (tokenize.STRING, tokenize.COMMENT):
                continue
            (sr, sc), (er, ec) = token.start, token.end
            for row in range(sr - 1, er):
                chars = list(lines[row])
                left = sc if row == sr - 1 else 0
                right = ec if row == er - 1 else len(chars)
                for col in range(left, min(right, len(chars))):
                    if chars[col] != chr(10) and chars[col] != chr(13):
                        chars[col] = ' '
                lines[row] = ''.join(chars)
    except (tokenize.TokenError, IndentationError):
        return '\n'.join('' for _ in content.splitlines())
    return ''.join(lines)

def scan_file(filepath, relative_path=None):
    findings = []
    rel_path = relative_path or os.path.basename(filepath)
    ext = os.path.splitext(filepath)[1].lower()
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as handle:
            content = handle.read()
    except OSError:
        return findings

    if ext == ".py":
        try:
            visitor = CryptoASTVisitor(rel_path)
            visitor.visit(ast.parse(content, filename=rel_path))
            findings.extend(visitor.findings)
        except SyntaxError as exc:
            findings.append(_finding(f"{rel_path}:{exc.lineno or 1}", "Python parse error",
                "Scanner limitation", "Parse error", str(exc), None, asset_type="Scanner diagnostic"))

    findings.extend(_scan_language_lines(content, rel_path, ext))
    text_content = _mask_python_strings_and_comments(content) if ext == '.py' else content
    for line_no, raw_line in enumerate(text_content.splitlines(), 1):
        line = _strip_line_comment(raw_line, ext)
        if not line.strip():
            continue
        for pattern, algorithm, purpose, vulnerable in TEXT_PATTERNS:
            if pattern.search(line):
                findings.append(_finding(f"{rel_path}:{line_no}", algorithm, purpose,
                    "Textual indicator", line.strip()[:240], vulnerable))

    # Remove exact duplicates produced by overlapping API and keyword rules.
    unique = {}
    for item in findings:
        key = (item["location"], item["algorithm"], item["purpose"], item["evidence"])
        unique[key] = item
    return list(unique.values())


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


def parse_go_mod(filepath, rel_path):
    rows = []
    in_block = False
    try:
        with open(filepath, encoding="utf-8", errors="replace") as handle:
            for line_no, raw in enumerate(handle, 1):
                line = raw.split("//", 1)[0].strip()
                if line.startswith("require ("):
                    in_block = True
                    continue
                if in_block and line == ")":
                    in_block = False
                    continue
                if line.startswith("require "):
                    line = line[len("require "):].strip()
                elif not in_block:
                    continue
                parts = line.split()
                if len(parts) >= 2 and not parts[0].startswith("("):
                    rows.append(_dependency(parts[0], parts[1], f"{rel_path}:{line_no}"))
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
            elif lower == "go.mod":
                all_findings.extend(parse_go_mod(fullpath, rel_path))
            elif os.path.splitext(lower)[1] in SOURCE_EXTENSIONS:
                all_findings.extend(scan_file(fullpath, rel_path))
    return all_findings

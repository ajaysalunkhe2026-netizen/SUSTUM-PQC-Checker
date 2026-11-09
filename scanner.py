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

from dependency_inventory import parse_manifest

SKIP_DIRS = {".git", "__pycache__", "node_modules", "venv", ".venv", "dist", "build", "target"}
SOURCE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".json", ".yaml", ".yml", ".env", ".properties"}
DEPENDENCY_FILES = {"requirements.txt", "pyproject.toml", "Pipfile", "Pipfile.lock", "package.json", "package-lock.json", "npm-shrinkwrap.json", "go.mod", "go.sum"}

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
        self.crypto_objects = {}
        self.crypto_wrappers = {}

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

    def _resolve_alias(self, name):
        """Resolve imported and simple assignment aliases without executing code."""
        parts = name.split(".")
        seen = set()
        while parts and parts[0] in self.aliases and parts[0] not in seen:
            seen.add(parts[0])
            target = self.aliases[parts[0]]
            name = target + ("." + ".".join(parts[1:]) if len(parts) > 1 else "")
            parts = name.split(".")
        return name

    def _visit_scoped_node(self, node):
        # Keep local aliases from leaking into sibling functions/classes.
        previous_aliases = self.aliases.copy()
        previous_objects = self.crypto_objects.copy()
        self.generic_visit(node)
        self.aliases = previous_aliases
        self.crypto_objects = previous_objects

    def visit_FunctionDef(self, node):
        before = len(self.findings)
        self._visit_scoped_node(node)
        # Register same-file wrappers whose bodies directly invoke a recognized API.
        direct = [item for item in self.findings[before:]
                  if item.get("confidence") == "High-confidence API call"]
        if direct:
            self.crypto_wrappers[node.name] = direct[0]

    def visit_AsyncFunctionDef(self, node):
        self._visit_scoped_node(node)

    def visit_ClassDef(self, node):
        self._visit_scoped_node(node)

    def _generation_algorithm(self, name):
        low = name.lower()
        for marker, algorithm in (
            ("rsa.generate_private_key", "RSA"),
            ("ec.generate_private_key", "Elliptic Curve"),
            ("dsa.generate_private_key", "DSA"),
            ("dh.generate_parameters", "Diffie-Hellman"),
        ):
            if marker in low:
                return algorithm
        return None

    def _track_assignment(self, targets, value):
        for assigned in targets:
            if not isinstance(assigned, ast.Name):
                continue
            if isinstance(value, (ast.Name, ast.Attribute)):
                target = self._resolve_alias(_dotted_name(value))
                self.aliases[assigned.id] = target
                if isinstance(value, ast.Name) and value.id in self.crypto_objects:
                    self.crypto_objects[assigned.id] = self.crypto_objects[value.id]
                else:
                    self.crypto_objects.pop(assigned.id, None)
            elif isinstance(value, ast.Call):
                called = self._resolve_alias(_dotted_name(value.func))
                algorithm = self._generation_algorithm(called)
                if algorithm:
                    self.crypto_objects[assigned.id] = algorithm
                else:
                    self.crypto_objects.pop(assigned.id, None)
                self.aliases.pop(assigned.id, None)
            else:
                self.aliases.pop(assigned.id, None)
                self.crypto_objects.pop(assigned.id, None)

    def visit_Assign(self, node):
        self._track_assignment(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self._track_assignment([node.target], node.value)
        self.generic_visit(node)

    def visit_Call(self, node):
        name = self._resolve_alias(_dotted_name(node.func))
        low = name.lower()
        if isinstance(node.func, ast.Name) and name in self.crypto_wrappers:
            wrapped = self.crypto_wrappers[name]
            self.findings.append(_finding(
                f"{self.filename}:{node.lineno}", wrapped["algorithm"],
                "Wrapper invocation: " + wrapped["purpose"],
                "Interprocedural wrapper call",
                f"{node.func.id}() resolves to {name}() wrapping {wrapped['evidence']}",
                wrapped.get("vulnerable")))
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            object_name = node.func.value.id
            operation = node.func.attr.lower()
            if object_name in self.crypto_objects and operation in {"sign", "verify", "exchange", "decrypt", "encrypt"}:
                purpose = {
                    "sign": "Signature",
                    "verify": "Signature verification",
                    "exchange": "Key establishment",
                    "decrypt": "Decryption",
                    "encrypt": "Encryption",
                }[operation]
                self.findings.append(_finding(
                    f"{self.filename}:{node.lineno}", self.crypto_objects[object_name], purpose,
                    "Contextual data-flow", name, True))
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
            elif (name.split(".")[-1].lower() in {"sign", "verify", "exchange"} and self.aliases
                  and any(token in low for token in ("cryptography", "nacl", "oqs", "crypto"))
                  and not (isinstance(node.func, ast.Attribute)
                           and isinstance(node.func.value, ast.Name)
                           and node.func.value.id in self.crypto_objects)):
                operation = name.split(".")[-1].lower()
                self.findings.append(_finding(f"{self.filename}:{node.lineno}", "Cryptographic operation",
                    PY_CALLS[operation], "Contextual API call", name, None))
        self.generic_visit(node)


def _strip_source_comments(content, ext):
    """Mask comments while preserving strings and line numbers.

    Handles // and multi-line /* */ comments in C-like languages, and # comments
    in common config/shell files. Python comments are handled by tokenize.
    """
    if ext == ".py":
        return content
    hash_comments = ext in {".yaml", ".yml", ".env", ".properties", ".sh"}
    output = []
    quote = None
    escaped = False
    in_block = False
    in_line = False
    i = 0
    while i < len(content):
        char = content[i]
        nxt = content[i + 1] if i + 1 < len(content) else ""
        if in_line:
            if char == "\\n":
                in_line = False
                output.append(char)
            else:
                output.append(" ")
            i += 1
            continue
        if in_block:
            if char == "*" and nxt == "/":
                output.extend((" ", " "))
                in_block = False
                i += 2
            else:
                output.append("\\n" if char == "\\n" else " ")
                i += 1
            continue
        if quote:
            output.append(char)
            if escaped:
                escaped = False
            elif ord(char) == 92:
                escaped = True
            elif char == quote:
                quote = None
            i += 1
            continue
        if char in (chr(39), chr(34), chr(96)):
            quote = char
            output.append(char)
            i += 1
            continue
        if hash_comments and char == "#":
            in_line = True
            output.append(" ")
            i += 1
            continue
        if not hash_comments and char == "/" and nxt == "/":
            in_line = True
            output.extend((" ", " "))
            i += 2
            continue
        if not hash_comments and char == "/" and nxt == "*":
            in_block = True
            output.extend((" ", " "))
            i += 2
            continue
        output.append(char)
        i += 1
    return "".join(output)


def _scan_language_lines(content, rel_path, ext):
    findings = []
    patterns = LANGUAGE_PATTERNS.get(ext, [])
    clean_content = _strip_source_comments(content, ext)
    source_lines = clean_content.splitlines()
    aliases = {}
    if ext in {".js", ".ts"}:
        for source_line in source_lines:
            match = re.search(
                r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:require\(\s*["']crypto["']\s*\)|crypto)\s*;?""",
                source_line)
            if match:
                aliases[match.group(1)] = "crypto"
            match = re.search(
                r"""import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+["']crypto["']""",
                source_line)
            if match:
                aliases[match.group(1)] = "crypto"
    elif ext == ".go":
        for source_line in source_lines:
            match = re.search(
                r"""\b(?:(\w+)\s+)?["']crypto/(rsa|ecdsa|ecdh|sha1|sha256)["']""",
                source_line)
            if match:
                aliases[match.group(1) or match.group(2)] = match.group(2)
    for line_no, raw_line in enumerate(source_lines, 1):
        line = raw_line
        for alias, canonical in aliases.items():
            line = re.sub(r'\\b' + re.escape(alias) + r'\\s*\\.', canonical + ".", line)
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
    comment_free = _strip_source_comments(content, ext)
    text_content = _mask_python_strings_and_comments(comment_free) if ext == '.py' else comment_free
    for line_no, raw_line in enumerate(text_content.splitlines(), 1):
        line = raw_line
        if not line.strip():
            continue
        if ext == ".py" and re.match(r"^\s*(?:from\s+\S+\s+import\b|import\b)", line):
            continue
        # If a recognized API is present, its arguments are API context, not
        # independent free-text algorithm mentions (e.g. createSign("RSA-SHA256")).
        has_api_context = any(re.search(pattern, line, re.I)
                              for pattern, *_ in LANGUAGE_PATTERNS.get(ext, []))
        if has_api_context:
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
            elif lower in {"pyproject.toml", "pipfile", "pipfile.lock",
                           "package-lock.json", "npm-shrinkwrap.json", "go.sum"}:
                all_findings.extend(parse_manifest(fullpath, rel_path))
            elif os.path.splitext(lower)[1] in SOURCE_EXTENSIONS:
                all_findings.extend(scan_file(fullpath, rel_path))
    return all_findings

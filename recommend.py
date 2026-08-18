NIST_RULES = [
    (("RSA", "Signature"), "ML-DSA-65", "Pure PQC", "NIST FIPS 204: RSA signatures should move to ML-DSA. Impact: Larger signature size."),
    (("RSA", "Certificate"), "ML-DSA-65 certificate", "Pure PQC", "NIST transition: replace RSA certs with PQC/hybrid PKI plan."),
    (("RSA", "Key Exchange"), "X25519 + ML-KEM-768", "Hybrid", "NIST/commercial: hybrid KEM during transition."),
    (("ECDSA", "Signature"), "ML-DSA-65", "Pure PQC", "NIST FIPS 204: ECDSA signatures should move to ML-DSA."),
    (("ECDSA", "Certificate"), "ML-DSA-65 certificate", "Pure PQC", "Replace ECC certificates as part of PQC PKI transition."),
    (("ECDH", "Key Exchange"), "X25519 + ML-KEM-768", "Hybrid", "TLS/key exchange: hybrid classical + ML-KEM."),
    (("X25519", "Key Exchange"), "X25519 + ML-KEM-768", "Hybrid", "Keep X25519 only as hybrid component, add ML-KEM."),
    (("TLS-1.2", "Key Exchange"), "TLS 1.3 + X25519/ML-KEM", "Hybrid", "Move to TLS 1.3, then hybrid KEM."),
    (("TLS-1.3", "Key Exchange"), "TLS 1.3 hybrid KEM", "Hybrid", "TLS 1.3 with hybrid key exchange."),
    (("SHA-1", "Hashing"), "SHA-256 or SHA-384", "Replace", "SHA-1 is deprecated; replace immediately."),
    (("AES-256", "Encryption"), "AES-256-GCM", "Continue current", "AES-256 remains acceptable for data at rest."),
    (("SHA-256", "Hashing"), "SHA-256 / SHA-384", "Continue current", "SHA-256 generally acceptable; SHA-384 if policy requires."),
]

CNSA_RULES = [
    (("RSA", "Signature"), "ML-DSA-87", "Pure PQC", "CNSA 2.0: ML-DSA-87 for signatures."),
    (("RSA", "Certificate"), "ML-DSA-87 certificate", "Pure PQC", "CNSA 2.0 PKI target is ML-DSA-87."),
    (("RSA", "Key Exchange"), "ML-KEM-1024", "Pure PQC", "CNSA 2.0: ML-KEM-1024 for key establishment."),
    (("ECDSA", "Signature"), "ML-DSA-87", "Pure PQC", "CNSA 2.0: ML-DSA-87."),
    (("ECDSA", "Certificate"), "ML-DSA-87 certificate", "Pure PQC", "CNSA 2.0 certificate target."),
    (("ECDH", "Key Exchange"), "P-384 + ML-KEM-1024", "Hybrid", "CNSA transition hybrid uses P-384 + ML-KEM-1024."),
    (("X25519", "Key Exchange"), "ML-KEM-1024", "Pure PQC", "X25519 is not a CNSA 2.0 target."),
    (("TLS-1.2", "Key Exchange"), "TLS 1.3 + ML-KEM-1024", "Pure PQC", "CNSA: prefer TLS 1.3 and CNSA 2.0 algorithms."),
    (("TLS-1.3", "Key Exchange"), "TLS 1.3 + ML-KEM-1024", "Pure PQC", "CNSA 2.0 key establishment."),
    (("SHA-1", "Hashing"), "SHA-384", "Replace", "CNSA requires SHA-384/512."),
    (("AES-256", "Encryption"), "AES-256", "Continue current", "AES-256 is in CNSA 2.0."),
    (("SHA-256", "Hashing"), "SHA-384", "Replace", "CNSA 2.0 prefers SHA-384."),
]


def match_rule(item, rules):
    algo = item["algorithm"].upper()
    purpose = item["purpose"]
    for (a, p), rec, mode, reason in rules:
        if a.upper() in algo and (p == purpose or p == "Certificate" and purpose == "Certificate"):
            return rec, mode, reason
    if item.get("source") == "Dependency":
        return "Confirm actual usage first", "Pending", "Dependency found; do not treat as confirmed crypto usage."
    if not item.get("vulnerable"):
        return "No change required", "Continue current", "Current algorithm is acceptable under selected guideline."
    return "Manual review", "Pending", "No exact guideline mapping for this finding."


def recommend(items, guideline="nist"):
    rules = CNSA_RULES if guideline == "cnsa" else NIST_RULES
    out = []
    for item in items:
        rec, mode, reason = match_rule(item, rules)
        row = dict(item)
        row["recommendation"] = rec
        row["mode"] = mode
        row["reason"] = reason
        out.append(row)
    return out


def decide(items):
    confirmed_vuln = [i for i in items if i.get("vulnerable") and i.get("confidence") in ["Confirmed", "Confirmed via AST", "Confirmed via AST / Multi-Lang"]]
    suspected = [i for i in items if "Suspected" in str(i.get("confidence"))]
    pending = [i for i in items if i.get("mode") == "Pending"]

    if not items:
        return "Conditional", "No crypto findings. Confirm scope or add more files."
    if confirmed_vuln and not suspected and not pending:
        return "Go", "Confirmed findings have clear guideline recommendations and limited selected-part impact."
    if suspected or pending:
        return "Conditional", "Recommendation exists, but suspected findings or unmapped items need review."
    return "Go", "No vulnerable confirmed findings. Current crypto can continue or is already acceptable."


def impact(items):
    files = sorted({i["location"].split(":")[0] for i in items if i.get("vulnerable")})
    
    # Detailed cryptographic size comparison for change & impact analysis
    size_comparison = [
        {"algorithm": "RSA-2048", "pub_key_size": "256 bytes", "sig_size": "256 bytes", "quantum_safe": "No"},
        {"algorithm": "ECDSA P-256", "pub_key_size": "64 bytes", "sig_size": "64 bytes", "quantum_safe": "No"},
        {"algorithm": "ML-DSA-65 (PQC)", "pub_key_size": "1,952 bytes", "sig_size": "3,309 bytes", "quantum_safe": "Yes"},
        {"algorithm": "ML-KEM-768 (KEM)", "pub_key_size": "1,184 bytes", "sig_size": "1,088 bytes (Ciphertext)", "quantum_safe": "Yes"}
    ]

    return {
        "part_changes": files[:20],
        "size_metrics": size_comparison,
        "overall_note": "Enterprise & Dynamic Analysis Note: Static code analysis detects explicit static assets. However, runtime dynamic key loading, environment variables (e.g., .env), and external plugins must undergo manual architectural review to ensure full cryptographic agility.",
    }


def generate_sbom(items, part_name="sample-part"):
    components = []
    for item in items:
        if item.get("source") == "Dependency" or item.get("library") != "-":
            components.append({
                "type": "library",
                "name": item.get("library") or item.get("algorithm"),
                "version": item.get("key_size", "unknown"),
                "scope": item.get("purpose"),
                "vulnerable_to_quantum": item.get("vulnerable", False)
            })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": part_name
            }
        },
        "components": components
    }
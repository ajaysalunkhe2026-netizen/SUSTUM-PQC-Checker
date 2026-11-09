"""Guideline mapping is advisory and deliberately conservative."""
NIST_RULES = [
    (("ECDSA", "Signature"), "ML-DSA-65", "PQC candidate", "Evaluate ML-DSA-65 under NIST FIPS 204."),
    (("ECDH", "Key establishment"), "ML-KEM-768 or an approved hybrid design", "PQC candidate", "Evaluate ML-KEM under NIST FIPS 203 and protocol-specific hybrid guidance."),
    (("SHA-1", "Hash"), "SHA-256 or SHA-384", "Review", "SHA-1 is deprecated for collision-resistant use; assess protocol and compatibility."),
]
CNSA_RULES = [
    (("ECDSA", "Signature"), "ML-DSA-87", "PQC candidate", "Evaluate CNSA 2.0 profile applicability and transition requirements."),
    (("ECDH", "Key establishment"), "ML-KEM-1024 with approved transition design", "PQC candidate", "Confirm CNSA 2.0 requirements and protocol profile."),
    (("SHA-1", "Hash"), "SHA-384 or SHA-512", "Review", "Assess CNSA 2.0 requirements and protocol context."),
]


def match_rule(item, rules):
    if item.get("asset_type") == "Dependency":
        return "Inspect package and actual crypto usage", "Inventory only", "A manifest entry is not proof that the dependency uses cryptography."
    if item.get("asset_type") != "Algorithm":
        return "Manual review", "Pending", "Scanner diagnostic or non-algorithm indicator; no migration mapping applied."
    algo = str(item.get("algorithm", "")).upper()
    purpose = str(item.get("purpose", ""))
    # RSA key generation alone does not reveal whether the key is used for
    # signatures, encryption, or key transport. Never infer ML-DSA vs ML-KEM.
    if algo == "RSA":
        return "Determine actual RSA key usage before selecting a replacement", "Manual review", "RSA can support different operations; static key-generation evidence is insufficient to choose a PQC replacement."
    for (needle, expected_purpose), rec, mode, reason in rules:
        if needle.upper() in algo and expected_purpose.lower() in purpose.lower():
            return rec, mode, reason
    if item.get("vulnerable") is False:
        return "No PQC migration action inferred", "Review context", "This indicator is not classified as quantum-vulnerable by this scanner."
    return "Manual review", "Pending", "No safe one-to-one mapping can be inferred from this static indicator."


def recommend(items, guideline="nist"):
    rules = CNSA_RULES if guideline == "cnsa" else NIST_RULES
    output = []
    for item in items:
        rec, mode, reason = match_rule(item, rules)
        row = dict(item)
        row.update({"recommendation": rec, "mode": mode, "reason": reason})
        output.append(row)
    return output


def decide(items):
    actionable = [x for x in items if x.get("vulnerable") is True and x.get("asset_type") == "Algorithm"]
    uncertain = [x for x in items if x.get("vulnerable") is None or x.get("mode") == "Pending"]
    if not items:
        return "Conditional", "No indicators found. This does not prove the codebase is free of cryptography."
    if actionable or uncertain:
        return "Review required", "Static indicators were found; validate context and plan migration before making a decision."
    return "Conditional", "No explicitly vulnerable algorithm indicators were found; static scanning cannot establish cryptographic safety."


def impact(items):
    files = sorted({x["location"].split(":")[0] for x in items if x.get("vulnerable") is True})
    return {
        "part_changes": files[:50],
        "size_metrics": [
            {"algorithm": "RSA-2048", "pub_key_size": "256 bytes", "sig_size": "256 bytes", "quantum_safe": "No"},
            {"algorithm": "ECDSA P-256", "pub_key_size": "64 bytes (uncompressed point varies by encoding)", "sig_size": "typically 64 bytes raw", "quantum_safe": "No"},
            {"algorithm": "ML-DSA-65", "pub_key_size": "1,952 bytes", "sig_size": "3,309 bytes", "quantum_safe": "Designed to resist known quantum attacks"},
            {"algorithm": "ML-KEM-768", "pub_key_size": "1,184 bytes", "sig_size": "1,088 bytes ciphertext", "quantum_safe": "Designed to resist known quantum attacks"}
        ],
        "overall_note": "Illustrative standardized parameter sizes, not measured application traffic. Static results do not discover runtime-loaded keys, remote services, or all cryptographic operations."
    }


def generate_sbom(items, part_name="sample-part"):
    """Return a CycloneDX 1.6 JSON-compatible component inventory candidate.

    Dependency versions are retained only when declared. Source findings are
    represented as cryptographic-asset components with evidence properties.
    Schema validation is a separate required verification step.
    """
    components = []
    seen = set()
    for index, item in enumerate(items, 1):
        if item.get("asset_type") == "Dependency":
            name = item.get("library") or item.get("algorithm") or "unknown-dependency"
            version = item.get("version", "unknown")
            key = ("library", name, version)
            if key in seen:
                continue
            seen.add(key)
            component = {"type": "library", "bom-ref": f"dependency-{index}",
                         "name": name, "version": version}
        else:
            name = item.get("algorithm") or "cryptographic-indicator"
            key = ("cryptographic-asset", name, item.get("location"))
            if key in seen:
                continue
            seen.add(key)
            component = {"type": "cryptographic-asset", "bom-ref": f"crypto-{index}",
                         "name": name}
        props = [
            {"name": "sustum:asset_type", "value": str(item.get("asset_type", "Algorithm"))},
            {"name": "sustum:location", "value": str(item.get("location", ""))},
            {"name": "sustum:purpose", "value": str(item.get("purpose", ""))},
            {"name": "sustum:confidence", "value": str(item.get("confidence", ""))},
            {"name": "sustum:evidence", "value": str(item.get("evidence", item.get("notes", "")))[:500]},
        ]
        if item.get("vulnerable") is not None:
            props.append({"name": "sustum:quantum_vulnerable_indicator", "value": str(bool(item["vulnerable"])).lower()})
        # Preserve dependency provenance without conflating manifest declarations,
        # lockfile records, or checksum observations.
        for field in ("ecosystem", "source_kind", "dependency_scope",
                      "dependency_relationship", "version_kind"):
            if item.get(field) is not None:
                props.append({"name": f"sustum:{field}", "value": str(item[field])})
        component["properties"] = props
        components.append(component)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"type": "application", "name": part_name}},
        "components": components
    }

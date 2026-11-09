"""Small, labelled regression corpus for scanner behavior.

This is a hand-authored smoke corpus, not a representative benchmark.
Metrics are case-level and must not be presented as production accuracy.
Run: python tests/evaluate_detection.py
"""
import json
import os
import tempfile
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import scan_directory


CASES = [
    {"id": "py-rsa-api", "label": "positive", "file": "crypto.py",
     "source": "from cryptography.hazmat.primitives.asymmetric import rsa\nkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n",
     "expected": "RSA"},
    {"id": "java-jca-rsa", "label": "positive", "file": "Crypto.java",
     "source": 'KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");\n',
     "expected": "RSA"},
    {"id": "node-rsa", "label": "positive", "file": "crypto.js",
     "source": "crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });\n",
     "expected": "RSA"},
    {"id": "go-rsa", "label": "positive", "file": "crypto.go",
     "source": "key, err := rsa.GenerateKey(rand.Reader, 2048)\n",
     "expected": "RSA"},
    {"id": "openssl-rsa", "label": "positive", "file": "crypto.c",
     "source": "RSA_generate_key_ex(rsa, bits, e, cb);\n",
     "expected": "RSA"},
    {"id": "comment-only", "label": "negative", "file": "plain.py",
     "source": "# RSA-2048 is mentioned only in this comment\nprint('hello')\n",
     "expected": None},
    {"id": "ordinary-python", "label": "negative", "file": "plain.py",
     "source": "def add(a, b):\n    return a + b\n",
     "expected": None},
    {"id": "ordinary-js", "label": "negative", "file": "plain.js",
     "source": "function greet(name) { return 'hello ' + name; }\n",
     "expected": None},
    {"id": "contextual-sign", "label": "ambiguous", "file": "sign.js",
     "source": "const signer = createSign('RSA-SHA256');\n",
     "expected": None},
    {"id": "string-mention", "label": "ambiguous", "file": "logging.py",
     "source": "message = 'RSA is mentioned in this diagnostic string'\n",
     "expected": None},
]


def evaluate_cases(cases=None):
    cases = cases or CASES
    results = []
    tp = fp = fn = tn = ambiguous_findings = 0
    with tempfile.TemporaryDirectory() as root:
        for case in cases:
            path = os.path.join(root, case["file"])
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(case["source"])
            findings = scan_directory(root)
            # Isolate this case's findings by its relative file path.
            case_findings = [item for item in findings
                             if item["location"].startswith(case["file"] + ":")]
            # Remove the file before the next case to avoid cross-case contamination.
            os.remove(path)
            detected = bool(case_findings)
            expected = case.get("expected")
            label = case["label"]
            if label == "positive":
                hit = any(item.get("algorithm") == expected for item in case_findings)
                tp += int(hit)
                fn += int(not hit)
            elif label == "negative":
                fp += int(detected)
                tn += int(not detected)
            else:
                ambiguous_findings += len(case_findings)
            results.append({"id": case["id"], "label": label,
                            "expected": expected,
                            "detected_algorithms": sorted({x.get("algorithm", "") for x in case_findings}),
                            "finding_count": len(case_findings)})
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision is not None and recall is not None and precision + recall else None)
    return {
        "scope": "hand-authored regression smoke corpus; case-level; not representative",
        "cases": len(cases), "positive_cases": tp + fn,
        "negative_cases": fp + tn,
        "ambiguous_cases": sum(1 for x in cases if x["label"] == "ambiguous"),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1,
        "ambiguous_findings": ambiguous_findings,
        "case_results": results,
    }


if __name__ == "__main__":
    print(json.dumps(evaluate_cases(), indent=2, sort_keys=True))

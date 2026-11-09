"""Evaluate provenance-backed real-world source excerpts.

Binary metrics use positive API-use callsites and negative non-crypto excerpts.
Ambiguous cases are reported separately and excluded from precision/recall.
This is a curated benchmark sample, not a statistically representative accuracy claim.
Run: python tests/evaluate_real_world.py
"""
import json
import os
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scanner import scan_file

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"


def _load(path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)["cases"]


def load_cases():
    cases = []
    for filename in (
        "real_world_positive.json",
        "real_world_negative.json",
        "real_world_ambiguous.json",
    ):
        cases.extend(_load(DATA / filename))

    # Retain the earlier purpose-labelled pilot cases in the same evaluation.
    # They are not independent of all later examples and are reported as such.
    legacy = _load(ROOT / "real_world_corpus.json")
    for case in legacy:
        item = {
            "id": "legacy-" + case["id"],
            "label": case["label"],
            "extension": case["extension"],
            "source": case["source"],
            "provenance": {
                "repository": case["provenance"]["repository"],
                "path": case["provenance"]["path"],
                "commit": case["provenance"]["commit"],
                "line_start": case.get("expected_callsite_line", 1),
                "line_end": case.get("expected_callsite_line", 1),
                "license": case["provenance"].get("license", "see upstream repository"),
                "url": case["provenance"].get("url"),
            },
            "expected_algorithm": case.get("expected_algorithm"),
            "expected_purpose": case.get("expected_purpose"),
            "legacy_pilot": True,
        }
        cases.append(item)
    return cases


def evaluate(cases=None):
    cases = cases or load_cases()
    tp = fp = fn = tn = ambiguous = 0
    results = []
    by_repo = defaultdict(Counter)
    source_files = set()

    with tempfile.TemporaryDirectory() as tmp:
        for case in cases:
            filename = case["id"] + case["extension"]
            path = os.path.join(tmp, filename)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(case["source"] + ("" if case["source"].endswith("\n") else "\n"))

            findings = scan_file(path, relative_path=filename)
            crypto_findings = [
                item for item in findings
                if item.get("asset_type") != "Scanner diagnostic"
            ]
            api_findings = [
                item for item in crypto_findings
                if "API" in str(item.get("confidence", ""))
            ]
            label = case["label"]
            repo = case["provenance"]["repository"]
            source_files.add((repo, case["provenance"]["path"]))
            expected_algorithm = case.get("expected_algorithm")
            expected_purpose = case.get("expected_purpose")

            if label == "positive":
                matching = api_findings
                if expected_algorithm:
                    matching = [
                        item for item in matching
                        if item.get("algorithm") == expected_algorithm
                    ]
                detected = bool(matching)
                tp += int(detected)
                fn += int(not detected)
                by_repo[repo]["tp" if detected else "fn"] += 1
            elif label == "negative":
                detected = bool(crypto_findings)
                fp += int(detected)
                tn += int(not detected)
                matching = []
                by_repo[repo]["fp" if detected else "tn"] += 1
            elif label == "ambiguous":
                detected = bool(crypto_findings)
                ambiguous += 1
                matching = []
                by_repo[repo]["ambiguous"] += 1
            else:
                raise ValueError("Unknown case label: " + str(label))

            purpose_match = (
                any(item.get("purpose") == expected_purpose for item in matching)
                if expected_purpose else None
            )
            results.append({
                "id": case["id"],
                "label": label,
                "repository": repo,
                "path": case["provenance"]["path"],
                "source_lines": [
                    case["provenance"]["line_start"],
                    case["provenance"]["line_end"],
                ],
                "detected": detected,
                "api_finding_count": len(api_findings),
                "crypto_finding_count": len(crypto_findings),
                "expected_algorithm": expected_algorithm,
                "expected_purpose": expected_purpose,
                "purpose_match": purpose_match,
                "findings": [
                    {
                        "algorithm": item.get("algorithm"),
                        "purpose": item.get("purpose"),
                        "confidence": item.get("confidence"),
                        "evidence": item.get("evidence"),
                    }
                    for item in crypto_findings
                ],
                "provenance_url": case["provenance"].get("url"),
                "legacy_pilot_case": case.get("legacy_pilot", False),
            })

    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    return {
        "scope": "curated source-backed benchmark; excerpts are not a representative sample",
        "total_cases": len(cases),
        "positive_cases": tp + fn,
        "negative_cases": fp + tn,
        "ambiguous_cases": ambiguous,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "repository_count": len({x["provenance"]["repository"] for x in cases}),
        "source_file_count": len(source_files),
        "by_repository": {
            repo: dict(counts) for repo, counts in sorted(by_repo.items())
        },
        "case_results": results,
    }


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2, sort_keys=True))

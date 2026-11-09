"""Evaluate the provenance-backed source excerpt pilot corpus.

This is a small diagnostic pilot, not an independently validated benchmark.
Run: python tests/evaluate_real_world.py
"""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scanner import scan_file

ROOT = Path(__file__).resolve().parent
CORPUS_PATH = ROOT / "real_world_corpus.json"


def evaluate():
    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    cases = corpus["cases"]
    results = []
    tp = fp = fn = tn = 0
    callsite_hits = purpose_hits = positive_total = 0

    with tempfile.TemporaryDirectory() as tmp:
        for case in cases:
            filename = case["id"] + case["extension"]
            path = os.path.join(tmp, filename)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(case["source"])

            findings = scan_file(path, relative_path=filename)
            algorithms = sorted({item.get("algorithm", "") for item in findings})
            label = case["label"]

            if label == "positive":
                positive_total += 1
                expected = case["expected_algorithm"]
                matching = [item for item in findings if item.get("algorithm") == expected]
                detected = bool(matching)
                tp += int(detected)
                fn += int(not detected)

                callsite_line = case.get("expected_callsite_line")
                callsite_match = any(
                    item.get("location", "").endswith(":" + str(callsite_line))
                    for item in matching
                )
                callsite_hits += int(callsite_match)

                expected_purpose = case.get("expected_purpose")
                purpose_match = any(
                    item.get("purpose") == expected_purpose for item in matching
                )
                purpose_hits += int(purpose_match)
            elif label == "negative":
                detected = bool(findings)
                fp += int(detected)
                tn += int(not detected)
                callsite_match = None
                purpose_match = None
            else:
                raise ValueError("Unsupported label for pilot case: " + str(label))

            results.append({
                "id": case["id"],
                "label": label,
                "expected_algorithm": case.get("expected_algorithm"),
                "detected_algorithms": algorithms,
                "finding_count": len(findings),
                "algorithm_case_match": detected if label == "positive" else None,
                "expected_callsite_line": case.get("expected_callsite_line"),
                "callsite_match": callsite_match,
                "expected_purpose": case.get("expected_purpose"),
                "purpose_match": purpose_match,
                "provenance": case["provenance"]["url"],
                "review_status": case["review_status"],
            })

    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    return {
        "scope": "small source-backed pilot; not independently validated or representative",
        "corpus_status": corpus["status"],
        "cases": len(cases),
        "positive_cases": positive_total,
        "negative_cases": len(cases) - positive_total,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "positive_callsite_matches": callsite_hits,
        "positive_callsite_total": positive_total,
        "positive_purpose_matches": purpose_hits,
        "positive_purpose_total": positive_total,
        "case_results": results,
    }


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2, sort_keys=True))

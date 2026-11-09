# P1.1 — Source-backed real-world detection benchmark

**Status:** First benchmark implementation complete; independent second-review sign-off remains outstanding.  
**Evaluated branch:** `feature/reliable-pqc-cbom`  
**Evaluation commit:** `fa95e9035e694095c4d1286815a5dd18764ac46a`  
**CI run:** [42554779069](https://github.com/ajaysalunkhe2026-netizen/SUSTUM-PQC-Checker/actions/runs/42554779069)

## Scope

The evaluator combines:
- 24 newly added source-backed API-use callsites;
- 18 source-backed negative-control excerpts;
- 10 ambiguous/manual-review excerpts, excluded from binary metrics; and
- 9 earlier source-backed pilot cases retained for continuity.

Total: **61 cases**, across **5 upstream repositories** and **29 unique source files**. Every newly added case records an immutable upstream commit, file path, source line range and license. The corpus files are under `tests/data/`; the earlier purpose-labelled pilot is `tests/real_world_corpus.json`.

Repositories sampled:
- `pyca/cryptography`
- `golang/go`
- `nodejs/node`
- `bcgit/bc-java`
- `openssl/openssl`

## Latest measured result

The GitHub Actions evaluator ran against commit `fa95e903` and completed successfully.

| Measure | Result |
|---|---:|
| Total cases | 61 |
| Positive API-use cases | 29 |
| Negative controls | 22 |
| Ambiguous cases (excluded from binary metrics) | 10 |
| True positives | 27 |
| False positives | 0 |
| False negatives | 2 |
| True negatives | 22 |
| Precision | 1.000 |
| Recall | 0.931 |
| F1 | 0.964 |

The positive evaluator requires an API-level finding; a textual algorithm mention alone does not count as a successful API detection. Negative controls fail if the scanner emits a crypto finding. Ambiguous cases are not counted as positive or negative.

### Results by upstream repository

| Repository | TP | FN | TN | FP | Ambiguous |
|---|---:|---:|---:|---:|---:|
| pyca/cryptography | 6 | 0 | 5 | 0 | 2 |
| golang/go | 7 | 1 | 5 | 0 | 1 |
| nodejs/node | 6 | 0 | 5 | 0 | 2 |
| bcgit/bc-java | 6 | 0 | 5 | 0 | 2 |
| openssl/openssl | 2 | 1 | 2 | 0 | 3 |

## Missed detections found

1. **Go dot-imported RSA key generation** — the source imports `crypto/rsa` with a dot import and calls `GenerateKey`. The scanner emits a textual RSA indicator from the import, but does not resolve the callsite as an API use. This is counted as a false negative for API-level detection.
2. **OpenSSL provider-based RSA key generation** — the source uses `EVP_PKEY_CTX_new_from_name(..., "RSA", ...)` followed by `EVP_PKEY_keygen_init`. The scanner reports the RSA string as a textual indicator, but does not identify the provider API/key-generation purpose. This is counted as a false negative for API-level detection.

These are useful concrete gaps for later scanner work. They were not patched as part of this corpus-only milestone, to avoid tuning the detector against the benchmark while measuring it.

## Methodology and limitations

- Labels were manually assigned from the cited upstream source context and the callsite semantics.
- The corpus is reproducible because upstream source references are pinned to commit SHAs.
- The ambiguous set is explicitly separated from binary metrics.
- The examples are short source excerpts, not complete project scans.
- Several examples are drawn from test suites and demos; multiple cases share the same upstream project or source file. They are not 61 statistically independent projects.
- Negative controls mean only that the selected excerpt has no target crypto API/algorithm use; they do not mean the parent repository contains no cryptography.
- **No independent second reviewer has signed off the labels yet.** The cases are source-grounded and manually reviewed, but they should remain provisional until a separate reviewer checks the expected label, purpose and context.
- This sample is not representative of production code, and these metrics must not be described as production accuracy, full language coverage or independent validation.

## Reproduction

From the repository root:

```bash
python tests/evaluate_detection.py
python tests/evaluate_real_world.py
```

The existing GitHub Actions workflow runs both evaluators after the unit/API test suite.

## Recommended next action

Have a second reviewer independently label the 61 cases without seeing the scanner output, resolve disagreements, then expand the corpus toward 100+ cases across more repositories and non-test application code. After that, use the confirmed false negatives to prioritize Go dot-import handling and OpenSSL provider API recognition.

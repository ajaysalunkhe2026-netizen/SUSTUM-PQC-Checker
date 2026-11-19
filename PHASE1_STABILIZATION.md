# Phase 1 — Engine Stabilization

**Status:** Implemented on `fix/phase1-engine-stabilization-validated`  
**Review PR:** #2 — targets `feature/reliable-pqc-cbom`; does not target `main`.

## Changes

### Scanner correctness
- Corrected single-line and block-comment newline handling so code after comments remains visible and line locations remain stable.
- Corrected JavaScript/TypeScript and Go import-alias regular-expression boundaries.
- Added Go dot-import API recognition and operation-specific purpose classification.
- Added an OpenSSL provider RSA key-generation-context indicator.
- Masked quoted strings before broad source-code text matching to reduce algorithm-name string false positives. API-specific matching still runs against the unmasked source after comment masking.
- Added normalized `confidence_level` values (`high`, `medium`, `low`), structured `evidence_detail`, and stable `detector_id` while retaining legacy `confidence` and `evidence` fields for compatibility.
- Malformed `package.json` inputs now produce explicit scanner diagnostics rather than silently returning an empty inventory.

### Resource limits
- Maximum source/manifest candidate file: 5 MiB.
- Maximum candidate files per directory scan: 10,000.
- Maximum aggregate candidate source/manifest bytes: 100 MiB.
- Maximum directory scan wall-clock budget: 60 seconds, checked between files.
- Symbolic links are skipped and directory traversal does not follow symlinked directories.

### ZIP ingestion
- Maximum compressed upload: 200 MiB (Flask request limit).
- Maximum archive entries: 10,000.
- Maximum total declared and actual extracted data: 500 MiB.
- Maximum individual extracted file: 100 MiB.
- Rejects traversal paths, symlinks, duplicate normalized paths, encrypted entries, and unsupported special-file types.
- Rejects suspicious compression ratios above 200:1 for entries larger than 1 MiB.
- Extracted byte counts are checked against ZIP metadata; files are created exclusively to avoid overwriting.

## Regression tests

Added `tests/test_phase1_hardening.py` for:
- Line/block comment masking and CRLF line preservation.
- Go import aliases and dot imports.
- OpenSSL provider API indicators.
- String-only algorithm references.
- Evidence/confidence metadata.
- Oversized files and symlink skipping.
- ZIP traversal, duplicate paths, symlink entries, and high compression ratios.

## CI validation

The Phase 1 workflow runs:
1. Python bytecode compilation.
2. Full `unittest` discovery.
3. Hand-authored detection regression evaluator.
4. Source-backed real-world evaluator.

The latest successful run is recorded in GitHub Actions run **44572522844**. A second existing MVP workflow also passed in run **44572522719**.

### Curated source-backed benchmark result

| Measure | Result |
|---|---:|
| Total cases | 61 |
| Positive API-use excerpts | 29 |
| Negative excerpts | 22 |
| Ambiguous/manual-review excerpts | 10 |
| True positives | 29 |
| False positives | 0 |
| False negatives | 0 |
| True negatives | 22 |
| Precision | 1.000 |
| Recall | 1.000 |
| F1 | 1.000 |

These are regression metrics on a curated excerpt corpus across five upstream repositories and 29 source files. They are **not** production accuracy estimates, a statistically representative sample, or independent external validation. The 10 ambiguous cases are excluded from binary metrics; some purpose classifications remain contextual and require review.

## Remaining limitations

- The 60-second budget is checked between files; it is not an OS-enforced hard kill for a currently executing file.
- The scanner is not process-isolated or sandboxed. It runs as part of the Flask process.
- Multi-language analysis remains a mixture of Python AST and language-specific heuristics; it is not compiler-grade semantic analysis.
- Static scanning does not prove reachability, runtime use, or complete cryptographic coverage.
- Dependency manifest inventory is not complete package-manager resolution and does not prove cryptographic usage.
- Authentication, authorization, multi-tenant isolation, production deployment hardening, and service-level abuse controls are outside this phase.

## Release gate

Phase 1 code and regression gates pass on the reviewed branch. Do not merge to `main` or describe the product as production-ready until the PR is reviewed, remaining limitations are accepted, and subsequent CBOM, architecture, and security phases are completed.

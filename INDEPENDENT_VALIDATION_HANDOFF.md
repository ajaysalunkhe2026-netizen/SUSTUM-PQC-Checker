# Independent Validation Handoff — SUSTUM PQC Checker

**Purpose:** provide an external reviewer with a reproducible, bounded validation package for the current development candidate.

**Candidate branch:** `feature/reliable-pqc-cbom`  
**Candidate status:** development / pre-release validation candidate.  
**Not claimed:** production readiness, complete cryptographic discovery, complete dependency resolution, regulatory compliance, or independent validation.

## 1. What is being submitted

SUSTUM is a Python/Flask static-analysis prototype that scans selected source files and dependency manifests, emits evidence-labelled findings, provides conservative advisory mappings, and generates a CycloneDX 1.6 JSON inventory candidate.

The supported source-analysis scope is deliberately bounded:
- Python AST analysis for selected crypto API patterns, imported aliases, simple function aliases, selected wrapper-body/callsite patterns, and limited same-scope key-object tracking.
- Heuristic patterns for selected Java, JavaScript/TypeScript, Go and C/C++ APIs.
- Dependency inventory for requirements.txt, package.json, go.mod, pyproject.toml, Pipfile, Pipfile.lock, npm package-lock/shrinkwrap and go.sum.
- CycloneDX 1.6 JSON schema validation using the CycloneDX Python library.

Dependency presence is inventory evidence only. It is not proof of crypto usage, runtime reachability, vulnerability, or transitive dependency completeness.

## 2. Reproduction environment and commands

Requirements: Python 3.10+.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python tests/evaluate_detection.py
python tests/evaluate_real_world.py
```

Expected evaluator outputs must be recorded from the submitted commit, not copied from an earlier run. Preserve complete stdout, Python version, OS, dependency versions, Git commit SHA, and run timestamp with the reviewer report.

## 3. Frozen source-backed benchmark

The current benchmark is documented in [P1_1_REAL_WORLD_BENCHMARK.md](P1_1_REAL_WORLD_BENCHMARK.md) and stored under `tests/data/` plus `tests/real_world_corpus.json`.

Current labelled set:
- 61 excerpt cases: 29 positive API-use cases, 22 negative controls, 10 ambiguous/manual-review cases.
- Five upstream repositories: pyca/cryptography, golang/go, nodejs/node, bcgit/bc-java and openssl/openssl.
- 29 unique source files.
- The source-backed cases include immutable upstream commit references, file paths and line ranges.

Previously measured baseline: TP=27, FP=0, FN=2, TN=22; precision=1.000, recall=0.931, F1=0.964. Ambiguous cases are excluded from binary metrics. This is a small, curated excerpt benchmark—not a statistically representative estimate of real-world production accuracy. Cases are not independent projects, and some come from tests or examples. The labels have not yet received independent second-reviewer sign-off.

Known benchmark misses:
1. Go dot-imported RSA key generation is not resolved to an API-level finding.
2. OpenSSL provider-based RSA key generation is reported only as a textual indicator, not as the expected API/purpose finding.

Do not tune the scanner against the benchmark during the independent blind review. Any later changes must be evaluated on a separately held-out set.

## 4. Recommended independent review protocol

1. Reviewer checks out the exact candidate commit and verifies the working tree is clean.
2. Reviewer receives the corpus labels and scanner output separately. For a genuinely blind pass, first provide only the pinned source excerpts, source context and annotation rubric—not the expected labels or scanner findings.
3. Reviewer independently labels each case as positive API use, negative control, or ambiguous; records algorithm/API/purpose where supported; cites the source lines; and records rationale.
4. Freeze the reviewer's annotations before revealing the existing labels or running the scanner.
5. Compare labels; adjudicate disagreements with a third reviewer or documented joint review. Never silently overwrite original labels.
6. Run all three commands in Section 2 on the exact candidate commit.
7. Report confusion matrix, precision, recall and F1 for binary cases; report ambiguous cases separately. Include per-language and per-repository breakdowns where sample sizes permit. State confidence intervals only if the reviewer chooses and documents a defensible statistical method.
8. Add newly discovered cases to a separate held-out evaluation set before changing detector logic. After fixes, retain the original frozen set as a regression set and record before/after results.
9. Validate CycloneDX output separately for schema conformance, semantic completeness, stable identifiers, duplicate handling, provenance and import into at least one independent CycloneDX consumer. Schema pass alone is not CBOM interoperability validation.
10. Deliver a signed or attributable review report listing scope, commit SHA, environment, exact commands, evidence, findings, limitations and unresolved issues.

## 5. Annotation rubric

- **Positive:** the excerpt contains an actual callsite or operation matching the defined target crypto API/use. A keyword, import, comment, documentation string or dependency declaration alone is not sufficient.
- **Negative:** the reviewed excerpt contains no target API-use callsite under the defined scope. This does not mean the parent repository is crypto-free.
- **Ambiguous:** the excerpt lacks sufficient context, or the signal cannot be reliably classified without broader code/build/runtime context.
- Record separately: algorithm or family, API/callsite, operation/purpose, language, source file, pinned commit, line range, and confidence/rationale.
- Do not infer key size, protocol, runtime reachability, algorithm purpose, or quantum-vulnerability status without supporting evidence.

## 6. Known limitations and out-of-scope claims

- The scanner is not compiler-grade and does not provide a complete parser, full interprocedural call graph, cross-file data flow, or complete alias/wrapper resolution.
- Runtime-loaded keys, remote services, HSMs, binary-only code, network endpoints and deployment configuration are not discovered.
- Dependency parsers are format-specific; no package manager is executed and no complete dependency graph is resolved. Go checksum records are not proof of direct dependencies.
- Malformed manifest diagnostics have initial test coverage, not exhaustive coverage of every format/version/invalid shape.
- CBOM schema validation does not establish semantic correctness, completeness or interoperability. Component relationships and duplicate/instance modelling require further external review.
- The application has no authentication, RBAC, tenant isolation, persistent audit trail, rate limiting or production deployment hardening. Do not expose it as a public multi-user service.
- Do not upload private keys, credentials, secrets, customer source code or sensitive production artifacts to an unapproved environment.

## 7. Reviewer report template

Record:
- Reviewer name/organization and review date
- Candidate commit SHA and clean/dirty working-tree status
- OS, Python version and installed dependency versions
- Exact commands and raw logs
- Independent labels and annotation rationale
- Confusion matrix and metrics, with ambiguous cases separated
- Per-language/repository results and sample-size caveats
- False-positive and false-negative examples
- CycloneDX schema and semantic/interoperability results
- Security observations and threat-model assumptions
- Severity-ranked findings, reproduction steps and recommendations
- Explicit statement of what was not tested

## 8. Acceptance decision

Independent validation should result in one of: **pass for the stated bounded scope**, **conditional pass with listed remediation**, or **fail**. A pass must not be generalized beyond the tested languages, API patterns, dependency formats, corpus, environment or CBOM properties. Production deployment requires a separate security and operational readiness review.

# SUSTUM PQC Checker

SUSTUM is an early-stage static-analysis prototype for identifying cryptography-related indicators in source files and dependency manifests, then producing an advisory inventory and a CycloneDX-formatted JSON candidate.

## Current scope

- Python AST indicators for selected asymmetric key-generation and cryptographic operation calls, including imported aliases, simple assigned function aliases, calls located inside wrapper function bodies, limited same-file wrapper callsite linkage (including a simple assigned alias to a discovered wrapper), and bounded same-scope key-object alias tracking into selected operations.
- Heuristic API-pattern discovery for selected Java, JavaScript/TypeScript, Go and C/C++ crypto APIs (including common JCA, WebCrypto/Node crypto, Go standard library and OpenSSL calls), with bounded simple Node.js `crypto` import aliases and Go `crypto/*` import aliases.
- Dependency inventory from requirements.txt, package.json, go.mod, pyproject.toml, Pipfile, Pipfile.lock, npm package-lock/shrinkwrap files, and go.sum checksum records. Declared constraints, lockfile versions, ecosystem, scope and provenance are retained where the source format provides them.
- NIST- or CNSA-oriented advisory mapping for a small set of detected indicators.
- ZIP upload API with file-count, archive-size, path-traversal and symlink checks.
- HTML report returned in the API response.
- JSON inventory export using CycloneDX 1.6 structure and SUSTUM evidence properties.
- Strict CycloneDX 1.6 JSON validation through the CycloneDX project's Python validator; validation status and errors are returned with each scan.
- A small, hand-authored detection regression smoke corpus with case-level TP/FP/FN/TN, precision, recall and F1 output in CI. Ambiguous cases are reported separately and excluded from binary metrics.
- A separate 9-case source-backed pilot corpus (5 positive, 4 negative) pinned to upstream commits across Python, JavaScript, Go, Java and C. It reports algorithm presence separately from API-callsite and purpose matches; labels are provisional and have not received independent external review.

## Important limitations

This is **not an enterprise-ready or production security product**. It is a static-analysis prototype.

- Dependency parsing is format-specific and does not run package managers or independently resolve dependency graphs. npm lock entries and Go checksum records are inventory evidence; a go.sum record is not, by itself, proof of a direct dependency. Python project metadata is parsed without evaluating environment markers or resolving extras. Unsupported lockfile variants and malformed manifests may yield incomplete inventory.\n- It does not perform runtime, binary, network, TLS endpoint, certificate-store, HSM, cloud, or remote-service discovery.
- A text match or dependency manifest entry does not prove that cryptography is used at runtime.
- Language support is heuristic and API-pattern based, not a complete compiler-grade parser. C-like and selected configuration comment masking handles quoted comment markers and multi-line block comments, but it is not a full language lexer and does not model every language-specific string, preprocessor, or template construct. Python imported aliases, simple assigned function aliases, wrapper-body and same-file wrapper-callsite discovery, and bounded same-scope key-object-to-operation tracking are covered by focused tests; general interprocedural wrapper mapping outside the tested Python same-file case, cross-file call graphs, branch-sensitive data-flow, reflection, generated code, macros, custom providers, complex indirect calls, arbitrary Java/C/C++ aliases, most JavaScript/Go wrapper calls and unsupported APIs may still be missed.
- Detection coverage is limited; absence of findings does not prove absence of cryptographic assets.
- Recommendations are advisory and require protocol, implementation, interoperability, vendor and policy review.
- Schema validation establishes structural conformance to the selected CycloneDX 1.6 JSON schema only; it does not certify the accuracy or completeness of crypto discovery or regulatory compliance.
- No authentication, authorization, tenant isolation, persistence, rate limiting, or production deployment hardening is provided.
- No cryptographic keys or secret values should be uploaded.

## Requirements

- Python 3.10+
- Dependencies in requirements.txt

Install:

~~~bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
~~~

## Run the dashboard locally

~~~bash
python app.py
~~~

Open http://127.0.0.1:5050/ in a browser. The dashboard uploads a ZIP to the local Flask service, displays returned static findings, and offers CBOM JSON and HTML report downloads. Recent scan history stores only archive names, finding counts and timestamps in that browser's local storage; it is not server-side history. The dashboard does not add authentication or make this service safe for public exposure.

## Run the API locally

~~~bash
python app.py
~~~

The service listens on http://127.0.0.1:5050.

Health check:

~~~bash
curl http://127.0.0.1:5050/health
~~~

Scan a ZIP archive:

~~~bash
curl -X POST http://127.0.0.1:5050/scan \
  -F "file=@sample-project.zip" \
  -F "guideline=nist" \
  -o scan-response.json
~~~

The JSON response includes report_html and sbom. Save report_html as an .html file and sbom as a .json file if you want local artifacts.

Supported guideline values: nist and cnsa.

## Run tests and detection regression evaluation

~~~bash
python -m unittest discover -s tests -v
python tests/evaluate_detection.py
python tests/evaluate_real_world.py
~~~

The first evaluator uses a hand-authored smoke corpus. The second evaluates 61 curated source-backed cases across five upstream repositories (29 positive, 22 negative, 10 ambiguous) with immutable commit and line provenance. Latest pilot result: TP=27, FP=0, FN=2, TN=22 (precision 1.00, recall 0.931, F1 0.964). These are curated excerpt-level regression metrics, not representative production accuracy. Labels have not received independent second-reviewer sign-off. See [P1.1 benchmark report](P1_1_REAL_WORLD_BENCHMARK.md) for methodology, missed cases and limitations.

## Project status

The current branch is a development branch. Passing local tests will demonstrate only that the included test cases pass; it will not establish detection accuracy, schema compliance, production readiness, or enterprise suitability.

## Industry-grade CBOM engineering status\n\nAn architecture audit and phased delivery/acceptance plan is recorded in [INDUSTRY_GRADE_ROADMAP.md](INDUSTRY_GRADE_ROADMAP.md). Initial dependency-inventory support is being expanded; this is not yet a complete dependency resolver or an industry-validated CBOM product.\n\n## Next engineering milestones

1. Obtain independent second-reviewer sign-off for the 61 source-backed cases and expand toward 100+ cases, including non-test application code.
2. Add parser-backed analysis, interprocedural alias/wrapper resolution and bounded data-flow analysis.
3. Extend dependency graph resolution, lockfile and transitive dependency intelligence.
4. Verify CBOM component completeness and interoperability against independently produced real-project inventories and CycloneDX tooling.
5. Build purpose-aware migration plans with explicit protocol, key-use and operational dependencies.
6. Add authentication, authorization/RBAC, audit logging, tenant isolation, quotas, storage isolation and deployment hardening before shared or hosted deployment.

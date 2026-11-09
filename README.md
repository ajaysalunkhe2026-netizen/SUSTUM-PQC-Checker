# SUSTUM PQC Checker

SUSTUM is an early-stage static-analysis prototype for identifying cryptography-related indicators in source files and dependency manifests, then producing an advisory inventory and a CycloneDX-formatted JSON candidate.

## Current scope

- Python AST indicators for selected asymmetric key-generation and cryptographic operation calls, including imported aliases, simple assigned function aliases, calls located inside wrapper function bodies, and bounded same-scope key-object alias tracking into selected operations.
- Heuristic API-pattern discovery for selected Java, JavaScript/TypeScript, Go and C/C++ crypto APIs (including common JCA, WebCrypto/Node crypto, Go standard library and OpenSSL calls).
- Dependency inventory from requirements.txt, package.json and go.mod.
- NIST- or CNSA-oriented advisory mapping for a small set of detected indicators.
- ZIP upload API with file-count, archive-size, path-traversal and symlink checks.
- HTML report returned in the API response.
- JSON inventory export using CycloneDX 1.6 structure and SUSTUM evidence properties.
- Strict CycloneDX 1.6 JSON validation through the CycloneDX project's Python validator; validation status and errors are returned with each scan.
- A small, labelled detection regression smoke corpus with case-level TP/FP/FN/TN, precision, recall and F1 output in CI. Ambiguous cases are reported separately and excluded from binary metrics.

## Important limitations

This is **not an enterprise-ready or production security product**. It is a static-analysis prototype.

- It does not perform runtime, binary, network, TLS endpoint, certificate-store, HSM, cloud, or remote-service discovery.
- A text match or dependency manifest entry does not prove that cryptography is used at runtime.
- Language support is heuristic and API-pattern based, not a complete compiler-grade parser. Python imported aliases, simple assigned function aliases, crypto calls inside wrapper bodies, and bounded same-scope key-object-to-operation tracking are covered by focused tests; general interprocedural wrapper mapping, cross-file call graphs, branch-sensitive data-flow, reflection, generated code, macros, custom providers, complex indirect calls and unsupported APIs may still be missed.
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
~~~

The evaluator uses a hand-authored smoke corpus. Its metrics are regression signals only, not representative accuracy estimates. Expand and independently review the corpus before using any metric externally.

## Project status

The current branch is a development branch. Passing local tests will demonstrate only that the included test cases pass; it will not establish detection accuracy, schema compliance, production readiness, or enterprise suitability.

## Next engineering milestones

1. Grow and independently review the labelled detection corpus; add real-project fixtures with permission and documented ground truth.
2. Add parser-backed analysis, interprocedural alias/wrapper resolution and bounded data-flow analysis.
3. Extend dependency graph resolution, lockfile and transitive dependency intelligence.
4. Verify CBOM component completeness and interoperability against independently produced real-project inventories and CycloneDX tooling.
5. Build purpose-aware migration plans with explicit protocol, key-use and operational dependencies.
6. Add authentication, authorization/RBAC, audit logging, tenant isolation, quotas, storage isolation and deployment hardening before shared or hosted deployment.

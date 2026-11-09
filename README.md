# SUSTUM PQC Checker

SUSTUM is an early-stage static-analysis prototype for identifying cryptography-related indicators in source files and dependency manifests, then producing an advisory inventory and a CycloneDX-formatted JSON candidate.

## Current scope

- Python AST indicators for selected asymmetric key-generation and cryptographic operation calls.
- Heuristic API-pattern discovery for selected Java, JavaScript/TypeScript, Go and C/C++ crypto APIs (including common JCA, WebCrypto/Node crypto, Go standard library and OpenSSL calls).
- Dependency inventory from requirements.txt, package.json and go.mod.
- NIST- or CNSA-oriented advisory mapping for a small set of detected indicators.
- ZIP upload API with file-count, archive-size, path-traversal and symlink checks.
- HTML report returned in the API response.
- JSON inventory export using CycloneDX 1.6 structure and SUSTUM evidence properties.
- Strict CycloneDX 1.6 JSON validation through the CycloneDX project's Python validator; validation status and errors are returned with each scan.

## Important limitations

This is **not an enterprise-ready or production security product**. It is a static-analysis prototype.

- It does not perform runtime, binary, network, TLS endpoint, certificate-store, HSM, cloud, or remote-service discovery.
- A text match or dependency manifest entry does not prove that cryptography is used at runtime.
- Language support is heuristic and API-pattern based, not a complete compiler-grade parser. Aliases, wrappers, reflection, generated code, macros, custom providers, indirect calls and unsupported APIs may be missed.
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

## Run tests

~~~bash
python -m unittest discover -s tests -v
~~~

## Project status

The current branch is a development branch. Passing local tests will demonstrate only that the included test cases pass; it will not establish detection accuracy, schema compliance, production readiness, or enterprise suitability.

## Next engineering milestones

1. Expand language/API coverage with parser-backed analysis and alias/data-flow support.
2. Add larger reproducible positive, negative, and ambiguous detection fixtures; measure precision/recall on a documented corpus.
3. Extend dependency-manifest and build-system coverage and add API contract/security tests.
5. Add authentication, authorization, audit logging, quotas, storage isolation and deployment hardening before any shared or hosted deployment.
6. Measure precision/recall on a documented corpus before publishing accuracy claims.

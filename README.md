# SUSTUM PQC Checker

SUSTUM is an early-stage static-analysis prototype for identifying cryptography-related indicators in source files and dependency manifests, then producing an advisory inventory and a CycloneDX-formatted JSON candidate.

## Current scope

- Python AST indicators for selected asymmetric key-generation and cryptographic operation calls.
- Text indicators in selected source/configuration file types.
- Dependency inventory from requirements.txt and package.json.
- NIST- or CNSA-oriented advisory mapping for a small set of detected indicators.
- ZIP upload API with file-count, archive-size, path-traversal and symlink checks.
- HTML report returned in the API response.
- JSON inventory export using CycloneDX 1.6 structure and SUSTUM evidence properties.

## Important limitations

This is **not an enterprise-ready or production security product**. It is a static-analysis prototype.

- It does not perform runtime, binary, network, TLS endpoint, certificate-store, HSM, cloud, or remote-service discovery.
- A text match or dependency manifest entry does not prove that cryptography is used at runtime.
- Detection coverage is limited; absence of findings does not prove absence of cryptographic assets.
- Recommendations are advisory and require protocol, implementation, interoperability, vendor and policy review.
- The generated JSON has not yet been validated against the official CycloneDX schema in the automated test suite. Do not represent it as schema-validated or compliance-certified.
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

1. Expand language/API coverage and add alias-aware AST analysis.
2. Add reproducible positive, negative, and ambiguous detection fixtures.
3. Validate generated CBOM against the official CycloneDX schema and document any extensions.
4. Add API contract tests, security tests, and CI.
5. Add authentication, authorization, audit logging, quotas, storage isolation and deployment hardening before any shared or hosted deployment.
6. Measure precision/recall on a documented corpus before publishing accuracy claims.

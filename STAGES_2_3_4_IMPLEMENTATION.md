# Stages 2–4 implementation record

Branch: stage2-4-browser-native. Base: fix/phase1-final. No merge or deployment has been performed.

## Stage 2 — CBOM model
- Normalized findings and dependency records with source location, evidence, confidence and quantum-vulnerability indicator.
- CycloneDX 1.6 cryptographic assets use native cryptoProperties and algorithmProperties. Custom SUSTUM properties preserve family, purpose, evidence and provenance.
- Dependency components distinguish declared inventory from observed source findings.
- Deterministic component ordering and stable internal references; internal reference integrity checks.
- Not yet externally schema-validated or round-trip tested by an independent consumer.

## Stage 3 — Browser-native
- Separate Vite + TypeScript static application.
- ZIP processing and static scanning in a dedicated Web Worker. No upload request or Flask API call.
- Input, entry count, per-file and aggregate extracted-candidate budgets; traversal and symlink entries rejected.
- Bounded pattern support only; no parity claim against Python scanner.

## Stage 4 — Intelligence and reporting
- Findings include purpose, evidence, source location, confidence and cautious migration guidance.
- UI includes scan summary, findings, dependency inventory, diagnostics and limitations.
- JSON, CSV and CycloneDX CBOM downloads.
- No compliance or exploitability verdict.

## Release gates still required
- Run npm test and npm run build on this exact branch.
- Validate CBOM against official CycloneDX 1.6 JSON Schema and at least one independent consumer.
- Expand scanner accuracy tests against frozen and held-out source corpus; measure per-language performance.
- Test malformed/hostile ZIPs, resource exhaustion, browser compatibility, accessibility and CSP.
- No production deployment until independent review and explicit owner approval.

CI note: browser-ci.yml is installed on the PR base branch so GitHub can evaluate this workflow for the candidate pull request.

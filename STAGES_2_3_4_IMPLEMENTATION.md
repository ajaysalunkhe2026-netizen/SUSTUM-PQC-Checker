# Stages 2–4 implementation record

Branch: `stage2-4-browser-native-clean`. Pull request: #5. Base: `fix/phase1-final`. No merge or deployment has been performed.

## Phase 2 — Browser-native scanner implementation

- Separate Vite + TypeScript static application; scanning does not call the Flask `/scan` endpoint and does not upload the archive.
- ZIP work runs in a dedicated Web Worker. The UI reports progress and permits cancellation by terminating the worker.
- Resource limits: 100 MiB archive, 5,000 total entries, 2,000 candidate files, 2 MiB per candidate file, 50 MiB aggregate candidate bytes, and 30-second elapsed checks between entries.
- Declared uncompressed sizes and suspicious compression ratios are checked before extracting candidate files; actual extracted sizes are checked again.
- Rejects absolute paths, Windows drive paths, traversal, malformed path segments, duplicate normalized paths and Unix symlinks.
- Detection and manifest coverage remain intentionally narrow. This is not feature parity with the Python scanner and is not a full language parser.
- **Status:** implementation work advanced; automated verification and browser runtime validation intentionally deferred to the final testing pass.

## Phase 3 — CBOM model

- Normalized findings and dependency records with source location, evidence, confidence and quantum-vulnerability indicator.
- CycloneDX 1.6 cryptographic assets use native cryptoProperties and algorithmProperties. Custom SUSTUM properties preserve family, purpose, evidence and provenance.
- Dependency components distinguish declared inventory from observed source findings.
- Deterministic component ordering and stable internal references; internal reference integrity checks.
- Official schema validation and independent-consumer interoperability remain outstanding.

## Phase 4 — Intelligence and reporting

- Findings include purpose, evidence, source location, confidence and cautious migration guidance.
- UI includes scan summary, findings, dependency inventory, diagnostics and limitations.
- JSON, CSV and CycloneDX CBOM downloads.
- No compliance or exploitability verdict.

## Deferred final verification and release gates

The owner requested that testing be performed at the end. The following are deliberately not represented as passed:
- Run npm test and npm run build on this exact branch.
- Validate CBOM against official CycloneDX 1.6 JSON Schema and at least one independent consumer.
- Expand scanner accuracy tests against frozen and held-out source corpus; measure per-language performance.
- Test malformed/hostile ZIPs, resource exhaustion, browser compatibility, accessibility and CSP.
- Review the diff and obtain explicit owner approval before any merge or production deployment.

The candidate is not deployed to the production website.

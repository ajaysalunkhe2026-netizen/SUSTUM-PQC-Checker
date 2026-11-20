# Stages 2–4 implementation record

Branch: `stage2-4-browser-native-clean`. Pull request: #5. Base: `fix/phase1-final`. No merge or deployment has been performed.

## Phase 2 — Browser-native scanner

- Separate Vite + TypeScript static application; scanning does not call Flask `/scan` and does not upload the selected archive.
- ZIP work runs in a dedicated Web Worker. The UI reports progress and permits cancellation by terminating the worker.
- Resource limits: 100 MiB archive, 5,000 total entries, 2,000 candidate files, 2 MiB per candidate file, 50 MiB aggregate candidate bytes, and 30-second elapsed checks before and after extraction operations.
- The UI rejects archives above 100 MiB using `File.size` before reading the archive into an `ArrayBuffer`. File selection is locked during an active scan and restored on cancellation/completion.
- Declared uncompressed sizes and suspicious compression ratios are checked before extracting candidate files; missing/invalid size metadata is rejected; actual extracted sizes are checked again.
- Directory entries receive path normalization, traversal and duplicate checks before being skipped.
- Rejects absolute paths, Windows drive paths, traversal, malformed path segments, duplicate normalized paths and Unix symlinks.
- RSA key generation remains primitive-undetermined until use is known; SHA-1 quantum impact is represented as unknown. Node `createHash("sha1")` is now an indicator.
- Multiple same-line occurrences are retained as separate findings.
- npm and Python version constraints are kept separate from resolved versions; requirements parsing handles common specifiers, extras, markers and direct references while surfacing unsupported pip directives.
- Detection and manifest coverage remain intentionally narrow. This is not feature parity with the Python scanner and is not a full language parser.

## Phase 3 — CBOM model and evidence

- Normalized finding and dependency records preserve source location, detector evidence, confidence, quantum-vulnerability indicator and a cautious migration recommendation.
- CycloneDX 1.6 cryptographic assets use native `cryptoProperties` with `algorithmProperties.primitive`; SUSTUM properties retain family, purpose, evidence and provenance.
- Dependency components retain ecosystem, version evidence, scope and manifest provenance. They are explicitly marked as declared dependencies and `crypto-use-confirmed=false`; manifest presence is never represented as proof of cryptographic use.
- Stable SHA-256-derived component references, deterministic component ordering, application-to-component dependency edges, and internal checks for duplicate/missing/dangling references are implemented.
- CBOM download is blocked when internal validation fails.
- Official schema validation and independent-consumer interoperability remain unverified release gates.

## Phase 4 — Findings intelligence and reporting

- Findings show algorithm, primitive/purpose context, source file and line, confidence, raw evidence, quantum-vulnerability indicator and a review recommendation.
- Interactive search, confidence filter and algorithm filter support triage. User-controlled source/evidence strings are rendered with `textContent`, not HTML interpolation.
- Summary metrics, dependency inventory, diagnostics and explicit limitations are shown.
- JSON and CycloneDX 1.6 CBOM downloads are provided. CSV includes recommendations and neutralizes formula-leading cell values to reduce spreadsheet formula injection risk.
- No compliance, exploitability or complete-inventory verdict is claimed.

## Final verification and release gates

The owner asked to defer testing until the final pass. No tests, build, browser runtime checks or schema validation have been run by this implementation pass. Do not treat implementation as verified or production-ready until the following are completed:

- Run `npm test` and `npm run build` on this exact branch (regression tests were added for the latest hardening). Recent GitHub Actions runs were created with a failed conclusion, but the available workflow-run inspection returned zero jobs, so the failure cause could not be established. Treat CI as unresolved, not passed.
- Validate generated CBOM against the official CycloneDX 1.6 JSON Schema and at least one independent consumer.
- Expand scanner accuracy testing against frozen and held-out source corpora; report precision/recall per supported language and keep ambiguous cases separate.
- Test malformed/hostile ZIPs, cancellation during extraction, resource exhaustion, browser compatibility, accessibility and CSP.
- Review the final diff and resolve the outstanding PR base-branch divergence before any merge.
- Obtain explicit owner approval before merge or production deployment.

The candidate is not deployed to the production website.

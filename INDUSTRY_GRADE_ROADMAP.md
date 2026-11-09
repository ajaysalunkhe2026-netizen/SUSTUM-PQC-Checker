# Industry-grade CBOM engineering plan

**Status:** Architecture audit recorded; Phase 1 dependency-inventory foundation implemented, with parser diagnostics and npm lockfile edge-case fixes added in the focused engineering sprint.
**Working branch:** `feature/reliable-pqc-cbom`
**Baseline commit audited:** `6324c214b5b764afb3d5c3b251a8017f1195a3a8`
**Main branch:** intentionally unchanged.

## 1. Current architecture audit

The current application is a Flask service with a ZIP upload endpoint, a filesystem scanner, advisory recommendation mapping, HTML reporting, and CycloneDX 1.6 JSON candidate generation.

Existing strengths:
- ZIP extraction includes path traversal, symlink, entry-count and uncompressed-size checks.
- Python has AST-based detection for selected API patterns; other languages use bounded regex-based heuristics.
- Findings carry source locations, evidence text, confidence labels and conservative notes.
- CycloneDX JSON is validated using the CycloneDX Python library.
- Unit/API tests and two detection evaluators run in GitHub Actions.
- The source-backed benchmark currently has 61 curated excerpt cases; its labels have not received independent second-reviewer sign-off.

Observed gaps to address:
- Dependency inventory now dispatches requirements.txt, package.json, go.mod, pyproject.toml, Pipfile, Pipfile.lock, npm package-lock/shrinkwrap and go.sum. This is format-specific parsing, not package-manager execution or complete dependency graph resolution.
- Selected formats retain declared-versus-locked version semantics, ecosystem, source kind, scope and relationship. npm lock package paths are retained as instance provenance; edge cases and package-manager-version coverage remain incomplete.
- Initial malformed TOML/JSON manifest inputs produce scanner diagnostics, but diagnostic coverage is not exhaustive.
- Cryptographic findings are represented as CycloneDX cryptographic-asset components with SUSTUM properties. Schema validity alone does not establish semantic completeness, provenance quality, or interoperability with other CBOM producers/consumers.
- CBOM component references are now deterministically derived from component identity and evidence location, and output ordering is normalized. The model still needs a formal normalized relationship graph and external semantic/interoperability validation.
- The upload API has no authentication, authorization, tenant isolation, persistent audit trail, or production deployment controls.
- Static source/manifest analysis cannot discover runtime-loaded keys, remote cryptographic services, HSM state, binary-only usage, or prove reachability.

## 2. Delivery phases and acceptance gates

### Phase 0 — Baseline and benchmark governance
- Preserve the current source-backed benchmark as a frozen baseline.
- Obtain an independent reviewer to label cases without seeing scanner output; record disagreements and adjudication.
- Expand examples across repositories, languages, and non-test application code.
- Keep ambiguous cases separate from binary metrics.
- Do not tune the detector against hidden evaluation examples.

**Exit gate:** reproducible baseline, reviewer protocol, documented disagreements, and regression evaluation in CI.

### Phase 1 — Dependency intelligence
- Add parsers for Python project/lock formats, npm lockfiles, and Go checksum/lock metadata where applicable.
- Preserve declared constraints separately from resolved versions.
- Distinguish direct/transitive and runtime/development/optional scopes where the source format supports it.
- Record manifest path, line/provenance where available, package ecosystem, package identifier, and parser diagnostics.
- Do not infer cryptographic usage merely from a package name.
- Treat unsupported, malformed, or ambiguous manifests as explicit diagnostics rather than silently dropping them. Initial TOML/JSON parse failures now emit scanner diagnostics; format coverage and diagnostic quality still need broader fixtures.

**Exit gate:** fixtures for supported manifest versions, parser error tests, deterministic inventory, and documented limits on dependency graph completeness.

### Phase 2 — CBOM data model and interoperability
- Define a normalized internal asset and relationship model before serialization.
- Use stable component identifiers and explicit dependency/relationship edges.
- Map only evidence-supported fields to CycloneDX 1.6 cryptographic assets and properties.
- Validate against the official schema and add semantic invariants beyond schema validation.
- Test round-trip parsing and interoperability with independent CycloneDX tooling and externally produced sample BOMs.
- Preserve provenance and distinguish observed, inferred, declared, and unknown values.

**Exit gate:** schema validation plus semantic tests, deterministic output, relationship checks, and documented interoperability results.

### Phase 3 — Source discovery improvements
- Prioritize known benchmark misses (Go dot imports and OpenSSL provider-based key generation).
- Add parser-backed language analysis incrementally.
- Expand alias, wrapper, and bounded data-flow support with explicit language/version scope.
- Keep source evidence and uncertainty attached to every finding.

**Exit gate:** expanded held-out regression corpus, measured precision/recall by language and detection category, and documented unsupported patterns.

### Phase 4 — User experience and reporting
- Add reviewable findings, filters, scan diagnostics, and JSON/CSV/HTML exports.
- Ensure reports distinguish dependency inventory from confirmed source API indicators.
- Avoid presenting advisory quantum-vulnerability indicators as proof of exploitability or compliance status.

**Exit gate:** API/UI tests, accessibility/basic usability review, export consistency tests.

### Phase 5 — Security and release readiness
- Threat-model archive ingestion and multi-user operation.
- Add authentication, authorization, tenant isolation, audit events, quotas, storage isolation, retention/deletion controls, and secure deployment configuration as required by the deployment model.
- Add dependency/security scanning, secret handling guidance, abuse/resource tests, and operational documentation.
- Conduct independent security review and resolve findings before any shared/hosted deployment.

**Exit gate:** documented threat model, security test evidence, independent review, operational runbooks, and explicit release limitations.

## 3. Quality rules

- No production accuracy claims based only on the curated excerpt corpus.
- No claim of independent validation until a separate reviewer has completed and documented it.
- No claim that a dependency is used cryptographically solely because it appears in a manifest.
- No algorithm, key size, protocol, or purpose is guessed when evidence is absent.
- Report implemented, tested, simulated, and proposed capabilities separately.
- Do not merge this development branch into main without explicit owner approval.

## 4. Initial schedule estimate

Planning estimate from the current baseline:
- Architecture/benchmark governance: 3–5 working days.
- Dependency intelligence: 1–2 weeks.
- CBOM model and interoperability: 2–3 weeks.
- Source discovery: 2–3 weeks.
- UX/reporting: 1–2 weeks.
- Security hardening and release testing: approximately 2 weeks.

Overall implementation estimate: **9–13 weeks**, subject to audit findings, scope, test results, and available review capacity. Independent validation is expected to require a further **2–4 weeks**. These are estimates, not committed delivery dates.

## 5. Focused engineering sprint — 9 November 2026

Completed on `feature/reliable-pqc-cbom`:
- Malformed Python TOML and JSON lockfile inputs now produce visible scanner diagnostics rather than silently returning an empty inventory (initial coverage; not every parser path has exhaustive diagnostics yet).
- npm lockfile `resolved` tarball URLs are no longer mislabeled as package versions when no semantic `version` is present.
- npm v2/v3 direct-versus-transitive classification now checks the root `node_modules/<name>` package path, avoiding marking a nested duplicate as direct merely because the same package name is a root dependency.
- Added regression tests for malformed manifest diagnostics, invalid npm lock root, missing npm version with resolved URL, and nested duplicate package relationship.
- CI passed for commit `3d822f59526700b0ec0cb9c5add0e33bbe8a08dc`: [GitHub Actions run 42557599143](https://github.com/ajaysalunkhe2026-netizen/SUSTUM-PQC-Checker/actions/runs/42557599143).

Remaining in this area: preserve npm package-instance identity through CBOM serialization, add package-manager/version-specific fixtures, cover more malformed shapes, and validate dependency relationships against real lockfiles. The sprint does not establish complete dependency resolution or production readiness.

## 7. Independent validation handoff readiness

A reviewer guide is available in [INDEPENDENT_VALIDATION_HANDOFF.md](INDEPENDENT_VALIDATION_HANDOFF.md). It defines the candidate scope, reproduction commands, blind label-review protocol, annotation rubric, known limitations and report template. The 61-case benchmark is frozen for the first external review; reviewers should annotate source excerpts before seeing scanner output and must not use this set for detector tuning.

The current candidate remains a pre-release static-analysis prototype. The handoff guide does not claim production readiness or complete CBOM interoperability. The independent reviewer must run all commands against the exact candidate commit and report results, not reuse historical metrics as a fresh validation outcome.

## 8. Immediate next implementation task

Before sending the candidate externally, record the final candidate commit SHA and successful CI run. Then ask the independent reviewer to perform blind corpus annotation, run the reproducibility commands, inspect false positives/false negatives, and test CycloneDX output with an independent consumer. Keep all remediation on `feature/reliable-pqc-cbom`; leave `main` untouched.

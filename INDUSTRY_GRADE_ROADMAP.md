# Industry-grade CBOM engineering plan

**Status:** Architecture audit recorded; Phase 1 dependency-inventory foundation implemented and under continued expansion.
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
- Dependency inventory currently parses package.json, requirements.txt and go.mod in the active scanner path. The code advertises pyproject.toml and Pipfile in a constant, but those formats are not dispatched by scan_directory.
- Lockfiles and reliable transitive dependency resolution are not yet supported.
- Dependency records do not consistently distinguish declared constraints from resolved versions, direct from transitive dependencies, or production from development scope.
- Cryptographic findings are represented as CycloneDX cryptographic-asset components with SUSTUM properties. Schema validity alone does not establish semantic completeness, provenance quality, or interoperability with other CBOM producers/consumers.
- Finding identity and relationships need a stable model; current component references are generated from scan iteration order.
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
- Treat unsupported, malformed, or ambiguous manifests as explicit diagnostics rather than silently dropping them.

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

## 5. Immediate next implementation task

Begin Phase 0 by freezing the current benchmark baseline and defining an independent label-review protocol. In parallel, start Phase 1 with dependency parser fixtures and a normalized dependency record that preserves declared-versus-resolved version and provenance. Keep changes on `feature/reliable-pqc-cbom`; leave `main` untouched.

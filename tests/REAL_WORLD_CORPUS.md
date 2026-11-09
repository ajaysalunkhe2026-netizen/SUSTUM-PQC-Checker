# Source-backed real-world detection pilot

## Purpose

This pilot supplements the hand-authored regression smoke corpus with short source excerpts from public upstream projects. Each case is pinned to an immutable upstream commit and records the source path, original line range, license, expected label, and rationale.

## Current status

- 9 cases: 5 positive and 4 negative.
- Languages represented: Python, JavaScript, Go, Java, and C.
- Projects represented: pyca/cryptography, Node.js, Go, Bouncy Castle, and OpenSSL.
- Labels are provisional source-context reviews performed while curating the excerpts. They have **not** received independent external reviewer sign-off.
- The pilot is not a representative sample of production repositories and must not be described as real-world accuracy validation.
- The corpus is intentionally small. The P1.1 target remains 50–100 source-backed cases, with a broader language and library mix and a second reviewer for labels.

## What the evaluator measures

Run:

```bash
python tests/evaluate_real_world.py
```

For positive cases it reports three distinct checks:

1. **Algorithm case match:** did the scanner emit the expected algorithm anywhere in the excerpt?
2. **Callsite match:** did it emit that algorithm at the expected API call line?
3. **Purpose match:** did it classify the expected purpose, such as key generation?

For negative cases, any finding counts as a false positive. This distinction matters: a scanner can mention the right algorithm because it saw an import or string while still failing to identify the actual operation or its purpose.

The existing CI job prints these results as a diagnostic baseline. The pilot evaluator does not fail the workflow merely because a known scanner gap is exposed. Do not combine its metrics with the hand-authored 23-case smoke corpus.

## Provenance and licensing

Each fixture's `provenance` object includes an immutable upstream commit URL, file path, original line range, and license information. The excerpts are deliberately short and retain source attribution through these links. Consult each upstream project's license before redistributing the fixtures outside this repository.

Projects and source files used:

- pyca/cryptography — dual Apache-2.0 / BSD-3-Clause; `tests/hazmat/primitives/test_rsa.py`.
- Node.js — project MIT license; `test/parallel/test-crypto-keygen.js` and `lib/path.js`.
- Go — BSD-3-Clause; `src/crypto/rsa/rsa_test.go` and `src/strings/strings_test.go`.
- Bouncy Castle — MIT; RSA provider test and string utility source.
- OpenSSL — Apache-2.0; `demos/pkey/EVP_PKEY_RSA_keygen.c`.

## Label review policy

A positive label requires source context showing a cryptographic API/algorithm operation, not merely a comment or a dependency name. A negative label requires source context with no crypto operation in the selected excerpt. Ambiguous examples should be separately labelled and excluded from binary metrics.

Before calling the corpus independently reviewed, a second reviewer should verify every label against the pinned source and record reviewer identity/date and any disagreement. Cases with uncertain labels remain provisional or ambiguous; do not force them into positive/negative classes.

## Initial baseline (feature branch, 2026-11-09)

The first CI evaluation of the 9 source-backed pilot cases completed successfully as a diagnostic run:

- Case-level: TP=4, FP=0, FN=1, TN=4; precision=1.00, recall=0.80, F1=0.89.
- Expected API callsite matched in 3 of 5 positive cases.
- Expected purpose matched in 2 of 5 positive cases.

Observed gaps:

- **Node.js destructured import:** the upstream test imports `generateKeyPairSync` by destructuring from `crypto` and calls it directly. The current scanner missed this RSA key-generation call.
- **Go dot import:** the algorithm was detected from the `crypto/rsa` import, but not at the actual `GenerateKey` callsite. This is an algorithm-presence match, not successful operation-level discovery.
- **OpenSSL provider API:** RSA was detected at the provider callsite, but the purpose remained a generic algorithm reference rather than key generation.

These results are a useful initial failure analysis, not a claim about general scanner accuracy. The Node.js miss is a confirmed false negative within this pilot. The Go and OpenSSL cases demonstrate why algorithm-only metrics can overstate operation and purpose coverage.


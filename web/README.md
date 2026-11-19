# SUSTUM browser-native candidate

## Local commands

```bash
cd web
npm install
npm test
npm run build
npm run dev
```

ZIP extraction and analysis run in a dedicated Web Worker. The browser app does not call the Flask `/scan` endpoint and does not upload the selected archive. The user can cancel an active scan; cancelling terminates the worker. The UI displays scan progress and hides stale results when a new scan begins.

## Resource and archive safety boundaries

- ZIP input max 100 MiB; 5,000 total entries; 2,000 candidate source/manifest entries; candidate file max 2 MiB; aggregate candidate bytes max 50 MiB; 30-second elapsed budget checked before and after extraction operations.
- Declared uncompressed file sizes and suspicious compression ratios (>200:1 for files over 1 MiB) are checked before extraction. Actual extracted sizes and declared-size mismatches are checked again.
- Original ZIP paths are normalized and checked for absolute paths, Windows drive paths, traversal, NUL/empty segments and duplicate normalized names. Unix symlink entries are rejected.
- JSZip parses the central directory in browser memory. These limits reduce decompression-bomb exposure but do not constitute a hardened archive sandbox or a hard real-time CPU/memory limit. The browser may still incur memory cost while parsing a large central directory.
- The 30-second budget is cooperative, not an OS-level hard timeout inside a single JSZip operation. The UI can terminate the worker manually.
- Encrypted or unsupported ZIP archives fail closed with a scan error from the ZIP parser.

## Detection and inventory limitations

- Heuristic API recognition is intentionally narrower than the Python scanner. No feature parity or complete-language coverage is claimed.
- Comment masking is lightweight lexical handling, not a full parser. Regex literals, nested template interpolation and language-specific raw/triple-quoted string forms are not comprehensively parsed.
- Basic dependency inventory covers package.json (dependencies, devDependencies, optionalDependencies and peerDependencies), requirements.txt and go.mod. It does not execute package managers or resolve complete dependency graphs.
- Manifest presence is recorded as declared evidence, not proof of cryptographic use.
- Heuristic static analysis cannot prove reachability or runtime use, and cannot discover binary-only crypto, remote services, HSMs, runtime-loaded keys or all language constructs. A clean scan does not prove cryptography is absent.

## CBOM and reporting

- CycloneDX 1.6 output includes native `cryptoProperties`, source evidence, confidence, migration recommendation and manifest provenance.
- Stable component references, application-to-component edges and internal duplicate/dangling-reference checks are implemented. A failed internal validation blocks the CBOM download.
- Findings can be searched and filtered by confidence and algorithm. JSON, CSV and CycloneDX CBOM exports are available. CSV formula-leading values are neutralized.
- Internal checks do not replace official JSON Schema validation or independent CBOM consumer interoperability; those remain release gates.

## Explicit exclusions

No authentication, server persistence, remote TLS scanning, binary analysis, HSM discovery, runtime-loaded key discovery, remote-service discovery or complete package-manager dependency resolution. No compliance or exploitability verdict.

This is a separate development candidate. It is not deployed to the production website.

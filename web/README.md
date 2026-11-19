# SUSTUM browser-native candidate

## Local commands

```bash
cd web
npm install
npm test
npm run build
npm run dev
```

ZIP extraction and analysis run in a dedicated Web Worker. The browser app does not call the Flask `/scan` endpoint and does not upload the selected archive. The user can cancel an active scan; cancelling terminates the worker.

## Resource and archive safety boundaries

- ZIP input max 100 MiB; 5,000 total entries; 2,000 candidate source/manifest entries; candidate file max 2 MiB; aggregate candidate bytes max 50 MiB; 30-second elapsed budget checked between entries.
- Declared uncompressed file sizes and suspicious compression ratios (>200:1 for files over 1 MiB) are checked before extraction. Actual extracted sizes are checked again.
- Original ZIP paths are normalized and checked for absolute paths, Windows drive paths, traversal, NUL/empty segments and duplicate normalized names. Unix symlink entries are rejected.
- JSZip parses the central directory in browser memory. These limits reduce decompression-bomb exposure but do not constitute a hardened archive sandbox or a hard real-time CPU/memory limit. The browser may still incur memory cost while parsing a large central directory.
- A 30-second budget is checked between entries, not enforced as an OS-level hard timeout inside a single JSZip operation. The UI can terminate the worker manually.
- Encrypted or unsupported ZIP archives fail closed with a scan error from the ZIP parser.

## Detection and inventory limitations

- Heuristic API recognition is intentionally narrower than the Python scanner. No feature parity or complete-language coverage is claimed.
- Comment masking is lightweight lexical handling, not a full parser. Regex literals, nested template interpolation and language-specific raw/triple-quoted string forms are not comprehensively parsed.
- Basic dependency inventory covers package.json, requirements.txt and go.mod. It does not execute package managers or resolve complete dependency graphs.
- Manifest presence is recorded as declared evidence, not proof of cryptographic use.
- Heuristic static analysis cannot prove reachability or runtime use, and cannot discover binary-only crypto, remote services, HSMs, runtime-loaded keys or all language constructs. A clean scan does not prove cryptography is absent.

## CBOM and release status

- CycloneDX 1.6 output includes native cryptoProperties, source evidence, confidence and manifest provenance.
- Internal reference checks exist. Official schema validation and independent-consumer interoperability are release gates, not yet claimed as completed.
- No auth, server persistence, remote TLS, binary, HSM, runtime-loaded key or remote-service discovery.

This is a separate development candidate. It is not deployed to the production website.

# SUSTUM browser-native candidate

## Local commands

```bash
cd web
npm install
npm test
npm run build
npm run dev
```

ZIP extraction and analysis run in a dedicated Web Worker. The browser app does not call the Flask /scan endpoint and does not upload the selected archive.

## Resource and security boundaries

- ZIP input max 100 MiB; 5,000 total entries; candidate source file max 2 MiB; aggregate candidate bytes max 50 MiB; 30-second elapsed budget checked between entries.
- Original ZIP paths are checked for absolute paths and traversal; Unix symlink entries are rejected.
- JSZip parses the archive in browser memory; per-file and aggregate decompressed byte limits reduce, but do not eliminate, hostile-archive resource risks.
- Heuristic API recognition is intentionally narrower than the Python scanner. No feature parity or complete-language coverage is claimed.
- Basic dependency inventory covers package.json, requirements.txt and go.mod. It does not execute package managers or resolve complete dependency graphs.
- CycloneDX 1.6 output includes native cryptoProperties, source evidence, confidence and manifest provenance. CI validates a generated fixture against the official JSON Schema; this does not prove semantic completeness or independent-consumer interoperability.
- No auth, server persistence, remote TLS, binary, HSM, runtime-loaded key or remote-service discovery.

This is a separate development candidate. It is not deployed to the production website.

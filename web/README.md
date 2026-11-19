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

## Explicit limitations

- ZIP input max 100 MiB; 5,000 entries; candidate source file max 2 MiB; aggregate candidate bytes max 50 MiB.
- Heuristic API recognition is intentionally narrower than the Python scanner and is not compiler-grade. No feature parity is claimed.
- Basic dependency inventory covers package.json, requirements.txt and go.mod. No package manager execution or complete graph resolution.
- Comments are masked with lightweight patterns, not full language lexers.
- CycloneDX 1.6 output has internal reference checks. Official schema validation and independent consumer round-trip tests remain release gates.
- Browser-local execution reduces server-side source exposure but does not make hostile ZIPs harmless or eliminate browser resource exhaustion risks.
- No auth, server persistence, remote TLS, binary, HSM, runtime-loaded key or remote-service discovery.

This is a separate development candidate. It is not deployed to the production website.

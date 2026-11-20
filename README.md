# SUSTUM PQC Checker

Independent lab work by Ajay Salunkhe.

Static indicators in source and dependency manifests → advisory mapping → CycloneDX-formatted JSON candidate.

Not an estate inventory. Not a compliance certificate. Not a production security product.

## Repository branch notice

The GitHub default branch is currently `main`, which contains an older implementation and is not the maintained prototype baseline.

The current development source of truth is **`stage2-4-browser-native-clean`**. Switch to that branch before following its implementation documentation:

```bash
git clone --branch stage2-4-browser-native-clean https://github.com/ajaysalunkhe2026-netizen/SUSTUM-PQC-Checker.git
cd SUSTUM-PQC-Checker
```

Do not interpret this legacy `main` branch as having the feature set documented on the development branch. The browser-native candidate is documented in [web/README.md](web/README.md); the Python/Flask prototype and its limits are documented in the development-branch [README.md](https://github.com/ajaysalunkhe2026-netizen/SUSTUM-PQC-Checker/blob/stage2-4-browser-native-clean/README.md).

## What this project is

A lab-oriented static-analysis prototype. It looks for selected cryptography-related indicators in source code and dependency manifests and maps those indicators to advisory information. Output is an inventory candidate, not proof that an algorithm is reachable or used at runtime.

## Important limitations

- Detection is heuristic and incomplete. No findings does not mean no cryptography exists.
- Dependency declarations are inventory evidence, not proof of cryptographic use or a fully resolved dependency graph.
- Runtime behavior, binaries, live TLS traffic, remote services, HSMs, certificate stores and runtime-loaded keys are outside the stated scan scope.
- Recommendations are advisory and require human review of protocol, implementation, interoperability, vendor and policy context.
- CycloneDX-formatted output is a candidate inventory artifact; its presence does not establish complete CBOM coverage or compliance.
- This repository does not claim production suitability, security certification, or zero false positives.

For the maintained scope and detailed caveats, use the development-branch README linked above.

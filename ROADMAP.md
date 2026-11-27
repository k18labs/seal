# Roadmap

- **M0 Foundation:** single Rust crate, library/CLI split, baseline docs, pinned toolchain, cross-platform CI. Implemented; auditing and release hardening remain.
- **M1 File integrity:** streaming SHA-256 and optional BLAKE3, human and JSON output. Implemented and covered by unit/integration tests.
- **M2 Signatures:** Ed25519 key generation, OpenSSH key encoding, detached versioned signatures, explicit trusted public key, encrypted private-key storage, file sign/verify, stable trust results. Implemented; independent format/security review remains.
- **M3 Manifests:** deterministic versioned manifest, strict parser and limits, safe traversal, signed manifest verification, unexpected/missing file detection. Implemented; cross-platform CI evidence and independent review remain.
- **M4 Hardening:** fuzzing, platform race analysis, dependency review, reproducibility, resource limits, independent format review where available. In progress; see remaining checklist below.
- **M5 Release candidate:** cross-platform builds, SBOM/provenance, bootstrap trust, measured performance and known limitations. Not yet complete; no production v1 release is authorized by this roadmap.

## Remaining before v1

- Confirm the six-target Linux, macOS, and Windows CI matrix passes on the remote GitHub runners.
- Add scheduled bounded fuzzing and run fuzz smoke tests.
- Run the manual comparative hash benchmark and extend measurements to signature operations, manifest generation, and peak RSS.
- Produce release archives, checksums, CycloneDX SBOM, and GitHub provenance attestations; verify provenance from a clean environment.
- Run the configured six-target clean rebuild comparison and record results.
- Obtain independent review of manifest, signature, and encrypted-key formats; do not describe this as an audit until one occurs.
- Inspect all remote CI/security/release workflow results and keep known limitations current.

No later milestone is represented as complete by this roadmap.

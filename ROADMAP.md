# Roadmap

- **M0 Foundation:** single Rust crate, library/CLI split, baseline docs, pinned toolchain, cross-platform CI. Initial implementation is in place; supply-chain auditing and release hardening remain.
- **M1 File integrity:** streaming SHA-256 and optional BLAKE3, human and JSON output. Implemented and covered by unit/integration tests.
- **M2 Signatures:** Ed25519 key generation, OpenSSH key encoding, detached versioned signatures, explicit trusted public key, file sign/verify, stable trust results. Functional implementation is in place; Windows ACL verification and encrypted key storage remain open hardening work.
- **M3 Manifests:** deterministic versioned manifest, strict parser and limits, safe traversal, signed manifest verification, unexpected/missing file detection.
- **M4 Hardening:** fuzzing, platform race analysis, dependency review, reproducibility, resource limits, independent format review where available.
- **M5 Release candidate:** cross-platform builds, SBOM/provenance, bootstrap trust, measured performance and known limitations.

No later milestone is represented as complete by this roadmap.

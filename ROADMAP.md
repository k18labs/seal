# Roadmap

- **M0 Foundation:** single Rust crate, library/CLI split, baseline docs, pinned toolchain, CI. In progress pending CI and supply-chain checks.
- **M1 File integrity:** streaming SHA-256 and optional BLAKE3, human and JSON output. Implemented; verification is recorded in the development report.
- **M2 Signatures:** Ed25519 key generation, strict key encoding, detached versioned signatures, explicit trusted public key, file sign/verify, stable trust results.
- **M3 Manifests:** deterministic versioned manifest, strict parser and limits, safe traversal, signed manifest verification, unexpected/missing file detection.
- **M4 Hardening:** fuzzing, platform race analysis, dependency review, reproducibility, resource limits, independent format review where available.
- **M5 Release candidate:** cross-platform builds, SBOM/provenance, bootstrap trust, measured performance and known limitations.

No later milestone is represented as complete by this roadmap.

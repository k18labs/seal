# Roadmap

- **M0 Foundation:** single Rust crate, library/CLI split, baseline docs, pinned toolchain, cross-platform CI. Implemented.
- **M1 File integrity:** streaming SHA-256 and optional BLAKE3, human and JSON output. Implemented and covered by unit/integration tests.
- **M2 Signatures:** Ed25519 key generation, OpenSSH key encoding, detached versioned signatures, explicit trusted public key, encrypted private-key storage, file sign/verify, stable trust results. Implemented; qualified external format/security review remains.
- **M3 Manifests:** deterministic versioned manifest, strict parser and limits, safe traversal, signed manifest verification, unexpected/missing file detection. Implemented; all six CI targets pass with the regression suite.
- **M4 Hardening:** fuzzing, platform race analysis, dependency review, reproducibility, resource limits, independent format review where available. In progress; bounded fuzz smoke, six-target reproducibility checks, and the current six-target CI matrix pass. Concurrent mutation and symlink-swap stress coverage is implemented; qualified external format/security review remains.
- **M5 Release candidate:** cross-platform builds, SBOM/provenance, bootstrap trust, measured performance and known limitations. Candidate artifacts and SBOM were produced for six targets; provenance was verified locally with `gh attestation verify`; benchmark results are recorded. A production v1 release is not authorized by this roadmap.

## Remaining before v1

- Obtain qualified external review of manifest, signature, and encrypted-key formats. An internal read-only design review found no confirmed format defect, but it is not a professional audit.
- Create a version-aligned release-candidate tag after the remaining review and hardening items are resolved; no production v1 tag is created here.

The verifier does not provide an atomic filesystem snapshot. Directory inputs must remain quiescent for meaningful verification.

No production release is represented as complete by this roadmap.

# Roadmap

- **M0 Foundation:** single Rust crate, library/CLI split, baseline docs, pinned toolchain, cross-platform CI. Implemented.
- **M1 File integrity:** streaming SHA-256 and optional BLAKE3, human and JSON output. Implemented and covered by unit/integration tests.
- **M2 Signatures:** Ed25519 key generation, OpenSSH key encoding, detached versioned signatures, explicit trusted public key, encrypted private-key storage, file sign/verify, stable trust results. Implemented; qualified external format/security review completed with no blocking findings reported by the maintainer.
- **M3 Manifests:** deterministic versioned manifest, strict parser and limits, safe traversal, signed manifest verification, unexpected/missing file detection. Implemented; all six CI targets pass with the regression suite.
- **M4 Hardening:** fuzzing, platform race analysis, dependency review, reproducibility, resource limits, and qualified format review. Complete for this candidate; bounded fuzz smoke, six-target reproducibility checks, CI, race regressions, and external review all have passing evidence. Review report is not included in this repository.
- **M5 Release candidate:** cross-platform builds, SBOM/provenance, bootstrap trust, measured performance and known limitations. Tag `v1.0.0-rc.1` and its manual artifact workflow completed; all six archives and the SBOM passed GitHub attestation verification, and all six archive SHA-256 files matched. Production `v1.0.0` publication remains a separate maintainer decision.

The maintainer reports the qualified external review found no blocking findings; its report is not included in this repository.

## Remaining before production v1

- Final production `v1.0.0` publication remains a separate maintainer decision; this release candidate is not a production release.

The verifier does not provide an atomic filesystem snapshot. Directory inputs must remain quiescent for meaningful verification.

No production release is represented as complete by this roadmap.

# Roadmap

This roadmap tracks proposed work after the `v1.0.0-rc.1` candidate. Items are ordered by user value and risk, not by dates. The core remains an offline-first, single-crate Rust utility; format or trust-policy changes need their own design and review before implementation.

## Completed through the v1 release candidate

- **M0 Foundation:** single Rust crate, library/CLI split, baseline docs, pinned toolchain, and cross-platform CI.
- **M1 File integrity:** streaming SHA-256 and optional BLAKE3, human and JSON output.
- **M2 Signatures:** Ed25519 key generation, OpenSSH key encoding, detached versioned signatures, explicit trusted public key, encrypted private-key storage, file sign/verify, and stable trust results. The maintainer reports qualified external format/security review found no blocking findings; its report is not included here.
- **M3 Manifests:** deterministic versioned manifests, strict parsing and limits, safe traversal, signed manifest verification, and unexpected/missing file detection.
- **M4 Hardening:** fuzz smoke runs, platform race regressions, dependency review, resource limits, reproducibility checks, and qualified format review. The review report is not included here.
- **M5 Release candidate:** six platform builds, SBOM, provenance attestations, bootstrap guidance, measured performance, and documented limitations. Tag `v1.0.0-rc.1` and its artifact workflow completed; all six archives and the SBOM passed GitHub attestation verification, and all six archive SHA-256 files matched.

The release candidate is not a production release. Publishing `v1.0.0` remains a separate maintainer decision.

## Next: release and documentation accuracy

- [ ] Record a maintainer go/hold decision for production `v1.0.0`; confirm the exact release contents, supported targets, and independent trust channels for every published verification method.
- [x] Refresh the README candidate status to reflect completed RC builds and checks.
- [x] Reconcile the threat-model wording about qualified format review and broader audits.
- [x] Make performance records identify the target, release build profile, source revision, run settings, and platform for each binary-size and timing result.
- [x] Publish a concise release checklist covering tag/version alignment, CI, checksums, provenance verification, and known limitations.

## v1.1 proposal: everyday CLI use

- [x] Generate and document shell completions for Bash, Zsh, Fish, and PowerShell; check that every completion includes the current command and option names.
- [x] Add optional progress reporting for long manifest create/verify operations. Keep progress on stderr, keep JSON stdout machine-readable, and test quiet and redirected-output behavior.
- [x] Add a read-only manifest inspection and comparison command for humans and scripts. Define deterministic text and JSON output, and make clear that comparing manifests does not verify the files on disk.
- [x] Document and test the JSON output and exit-code contract for every command, including stable mismatch and malformed-input examples.
- [x] Add copy-ready CI examples for hashing files and verifying signed release directories; include explicit trusted-key setup and failure behavior.

## Later: trust and release workflows

- [x] Write a key rotation and recovery guide covering independent fingerprint distribution, overlap during key changes, and how users stop trusting a retired key.
- [x] Add an example workflow that verifies Seal signatures/manifests and GitHub artifact provenance without treating a bundled public key as trusted.
- [x] Document GitHub Release archives as the initial binary installation channel, with checksum and provenance checks; defer package-manager support until user demand is known.
- [x] Record the decision to defer a built-in trusted-key bundle until concrete user needs justify its identity, selection, rotation, revocation, and storage design.

## Later: measured scale and manifest evolution

- [x] Extend benchmarks across file counts and sizes on Linux, macOS, and Windows; record target, source revision, repetitions, elapsed time, and peak memory.
- [x] Measure manifest creation and verification before changing traversal or hashing; retain streamed, bounded reads.
- [x] Keep hashing serial because the baseline does not compare a parallel implementation; consider it only after a comparative benchmark and a bounded-memory design.
- [x] Record that metadata, exclusions, or filesystem snapshots require a separate versioned format design and do not alter version 1 semantics.

## Permanent constraints and known limits

- Keep cryptography in established libraries; do not implement primitives.
- Keep formats strict and versioned, and reject unknown identifiers.
- Require explicit trusted public keys. Provenance authenticates build context, not software safety or publisher intent.
- Keep file processing streamed and bounded in memory.
- Directory verification does not provide an atomic filesystem snapshot. Inputs must remain quiescent for meaningful verification.
- The qualified external review report is not included in this repository; this is not a claim of a full independent implementation or dependency audit.

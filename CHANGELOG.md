# Changelog

## 0.1.1

- Add Ed25519 key generation, fingerprint inspection, file signing, and explicit-key verification using a versioned Seal record with OpenSSH SSHSIG.
- Add stable verification result codes and JSON verification output.
- Pin `ssh-key` 0.6.7 with only the required SSHSIG, Ed25519, OS-randomness, and standard-library features.

## Unreleased

- Add deterministic, bounded directory manifests with strict parsing and exact-tree verification.
- Add domain-separated manifest signatures and machine-readable verification results.
- Encrypt generated private keys with Argon2id and XChaCha20-Poly1305; apply Unix `0600` and verified protected Windows DACLs.
- Add hidden passphrase prompts and bounded passphrase-file support.
- Stream directory traversal through capability-scoped no-follow handles with file, path, byte, recursion, and entry limits.
- Add stdin hashing, fuzz targets, six-target CI/release workflows, manual benchmark and reproducibility workflows, checksums, SBOM generation, and provenance attestation.
- Raise the declared MSRV to Rust 1.87 to use a fixed `ctutils` release addressing a constant-time advisory.
- Add regression tests for prompt confirmation mismatch, partial-write rollback, concurrent replacement and symlink swaps, and bound CLI subprocess runtimes.
- Record remaining cross-platform workflow evidence and independent format/security review requirements in `ROADMAP.md`.

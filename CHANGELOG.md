# Changelog

## 0.1.1

- Add Ed25519 key generation, fingerprint inspection, file signing, and explicit-key verification using a versioned Seal record with OpenSSH SSHSIG.
- Add stable verification result codes and JSON verification output.
- Pin `ssh-key` 0.6.7 with only the required SSHSIG, Ed25519, OS-randomness, and standard-library features.

## Unreleased

- Initial Rust CLI foundation.
- Streaming SHA-256 and optional BLAKE3 file hashing.
- Human-readable and JSON output.

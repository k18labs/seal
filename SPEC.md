# Seal specification (initial implementation)

## Scope

Seal is an offline file-integrity CLI and reusable Rust library. Version 0.1.1 implements regular-file hashing using SHA-256 and optional BLAKE3, Ed25519 key generation, detached file signing and verification, and explicit trusted-key selection. It does not implement manifests or directory verification.

## Current behavior

- `seal hash PATH [--algorithm sha256|blake3] [--json]` hashes a regular file with a 65,536-byte buffer.
- SHA-256 is the default. Unknown algorithm values are rejected by the CLI parser.
- `seal version` prints the package version.
- `seal keygen --out PATH` generates an unencrypted OpenSSH Ed25519 private key at `PATH` and a public key at `PATH.pub`. Creation fails if either path already exists. Unix private-key creation mode is `0600`; on Windows the file inherits the destination directory's ACL.
- `seal key fingerprint --public-key PATH` prints the OpenSSH SHA-256 fingerprint. `seal key inspect --public-key PATH` reports Ed25519 and the fingerprint.
- `seal sign PATH --key PRIVATE --output SIGNATURE` signs a versioned file digest envelope and refuses to overwrite the signature output.
- `seal verify PATH --signature SIGNATURE --public-key PUBLIC [--json]` verifies with the explicitly provided key and checks the artifact's size and SHA-256 digest. The signature's embedded key is never accepted as trust by itself.
- Seal signature records have a strict 64 KiB input cap; key files have a 16 KiB cap.
- Human output is `<lowercase-hex-digest><two spaces><escaped path>`.
- JSON output is one UTF-8 JSON object with `algorithm`, `digest`, and `path` string fields. `path` uses the platform's lossy display conversion; the digest is computed from file bytes, not the path.
- Directories and other non-regular files are rejected. An I/O or type error produces no digest on stdout.
- Process exit status is 0 for success/help/version, 1 for content integrity mismatch, 2 for an invalid cryptographic signature, 3 for an invalid or untrusted public key, 4 for malformed input/key data, 5 for filesystem or output failures, 6 for invalid command-line usage, and 7 for unsupported algorithms or formats.

This specification describes the current implementation only. Future formats must have explicit versions and reject unsupported algorithms.

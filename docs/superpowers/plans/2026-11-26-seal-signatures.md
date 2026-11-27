# Seal File Signature Implementation Plan

**Goal:** Add Ed25519 key management and offline file signing and verification with bounded-memory hashing and explicit signer trust.

**Architecture:** Use OpenSSH SSHSIG via the maintained RustCrypto `ssh-key` crate. Seal signs a fixed versioned message containing SHA-256 and byte length; verification still requires a user-selected public key whose key data must equal the key embedded in SSHSIG.

**Tech Stack:** Stable Rust, `ssh-key` 0.6.7 with only `std`, `ed25519`, and `getrandom` features; existing SHA-256 streaming code.

**Spec:** `../../../SPEC.md` and `../../../docs/SIGNATURE_FORMAT.md`.

## Global Constraints

- “Security takes precedence over performance and binary size.”
- “Never trust a public key simply because it accompanies an artifact.”
- “Use domain separation for signed Seal objects.”
- “Support bounded-memory streaming.”
- “Never implement custom cryptographic algorithms.”

## Review Focus

- Wrong trusted key: reject before reporting success.
- Modified file, metadata, or signature: return nonzero with no success output.
- Future SSHSIG versions, algorithms, namespaces, and oversized inputs: reject explicitly.
- Existing key or signature output path: never overwrite.
- Private-key permissions: use restrictive Unix creation mode; document Windows inherited-ACL behavior.

---

### Task 1: SSHSIG format and key support

**Files:** `Cargo.toml`, `Cargo.lock`, `src/signature.rs`, `src/lib.rs`, `src/main.rs`, `docs/SIGNATURE_FORMAT.md`, `docs/KEY_MANAGEMENT.md`, `docs/CRYPTOGRAPHY.md`, `docs/adr/0002-sshsig.md`.

- [x] Add keygen, public-key inspect/fingerprint, and strict size-limited key parsing.
- [x] Add stable message-envelope construction: `SEAL-FILE-V1\0sha256\0 || u64_be(size) || digest[32]`.
- [x] Bind it to SSHSIG namespace `seal-file-v1` and SSHSIG hash algorithm `sha256`.
- [x] Add tests for fingerprint, key encoding, envelope determinism, and unsupported SSH key algorithms.

### Task 2: File sign and verify

**Files:** `src/hash.rs`, `src/signature.rs`, `src/main.rs`, `tests/signature_cli.rs`.

- [x] Add signing and verification commands, strict detached signature parsing, explicit trusted public key comparison, and stable exit codes.
- [x] Add integration coverage for valid round-trip, changed bytes, wrong key, signed metadata tampering, and no-overwrite behavior.
- [ ] Run formatting, locked tests, clippy, cross-platform CI, and record remaining key-permission limitations.

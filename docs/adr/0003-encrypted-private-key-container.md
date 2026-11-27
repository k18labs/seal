# ADR 0003: Encrypted private-key container

- **Status:** Implemented for the 1.0.0 release candidate; qualified external review completed with no blocking findings reported by the maintainer
- **Date:** 2026-11-26

## Context

Private keys must not be written in plaintext by default. The OpenSSH SSHSIG library can parse encrypted OpenSSH private keys, but its encryption uses a scrypt-based construction whose AEAD robustness warning did not meet this project's preference for a well-established authenticated-encryption primitive.

## Decision

Wrap the established OpenSSH Ed25519 private-key text in a fixed `SEAL-PRIVATE-KEY 1` container. Derive 32 bytes with Argon2id v19, 64 MiB, 3 iterations, 1 lane, random 16-byte salt. Encrypt with XChaCha20-Poly1305 using a random 24-byte nonce. Authenticate the complete magic/salt/nonce header as associated data. Reject malformed or unknown versions and never fall back to plaintext. KDF parameter changes require a new container version.

On Unix, create with mode `0600`. On Windows, create with no sharing, apply a protected DACL granting full access only to owner rights, SYSTEM, and Administrators, read back the ACL, and fail closed on mismatch before writing ciphertext.

## Consequences

The format is small and uses established primitives, but its container layout and KDF policy are Seal-specific. The maintainer reports qualified external review found no blocking findings; the report is not included in this repository. Passphrase strength remains the user's responsibility. Sensitive buffers are zeroized where available, but key parsing may create copies that first-party code cannot guarantee to erase. The passphrase-file option places responsibility for protecting and removing that file on automation users.

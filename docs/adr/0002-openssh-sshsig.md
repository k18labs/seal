# ADR 0002: OpenSSH SSHSIG for detached signatures

- **Status:** Accepted for the initial signature implementation
- **Date:** 2026-11-26

## Context

Seal needs bounded-memory file signing, explicit Ed25519 identity, and domain separation. Minisign is established but has a pre-hashed mode that is not RFC 8032 Ed25519ph, while the project requires precise separation between signed object types. OpenSSH SSHSIG has a detached, versioned encoding and a namespace included in signed data.

## Decision

Use the SSHSIG structure implemented by `ssh-key` 0.6.7, with Ed25519 and SSHSIG SHA-256. Files use namespace `seal-file-v1` and a 60-byte Seal envelope; manifests use `seal-manifest-v1` and a 64-byte envelope. The strict version-1 outer Seal record labels each signed object type.

Trust is separate from mathematical validity: verification requires an explicitly selected public key, verifies the signature, compares that key with the embedded SSHSIG key, then checks artifact size and digest.

## Consequences

The inner signature follows SSHSIG, but the Seal record and fixed messages are format-specific and need independent review. OpenSSH encrypted-key support is disabled. Seal stores encrypted OpenSSH private-key text in a separate versioned Argon2id/XChaCha20-Poly1305 container; see ADR 0003. Unix creation mode is restrictive, and Windows applies and verifies a protected DACL before writing key ciphertext.

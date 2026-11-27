# ADR 0002: OpenSSH SSHSIG for detached file signatures

- **Status:** Accepted for the initial signature implementation
- **Date:** 2026-11-26

## Context

Seal needs bounded-memory file signing, explicit Ed25519 identity, and domain separation. Minisign is established but has a pre-hashed mode that is not RFC 8032 Ed25519ph, while the project requires precise separation between signed object types. OpenSSH SSHSIG has a detached, versioned encoding and a namespace included in signed data.

## Decision

Use the SSHSIG structure implemented by `ssh-key` 0.6.7, with Ed25519, SSHSIG SHA-256, and namespace `seal-file-v1`. Hash the artifact with SHA-256 in a fixed-size buffer and sign a 60-byte Seal envelope containing object/version, algorithm, file size, and digest. Wrap SSHSIG PEM in a strict version-1 Seal record so the verifier can distinguish a valid signature over metadata from an artifact whose current bytes differ.

Trust is separate from mathematical validity: verification requires an explicitly selected public key, verifies the signature, compares that key with the embedded SSHSIG key, then checks artifact size and digest.

## Consequences

The inner signature follows SSHSIG, but the Seal record and fixed message are format-specific and need independent review. The OpenSSH private-key file is currently unencrypted. Unix creation mode is restrictive; Windows uses inherited directory ACLs, which Seal does not currently verify. `ssh-key`'s OpenSSH encryption feature is disabled; no custom private-key encryption format is created.

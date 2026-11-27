# Threat model

## Scope

This document covers file hashing and detached file signatures. Manifests, release trust, and directory traversal are not implemented.

## Assets and boundaries

- File bytes are read from a user-selected filesystem path.
- The local process and Rust hashing libraries are trusted for this operation.
- The expected digest and its delivery channel are outside Seal's control.
- The user-selected trusted public key and its delivery channel are outside Seal's control.
- The local OS, filesystem, and dependency implementations are trusted.

## Threats and controls

| Threat | Control | Verification and remaining limit |
|---|---|---|
| File content is changed while hashing | Digest is computed over bytes returned by the reader | Known vectors and read-error tests; concurrent writes may produce a digest of a changing byte stream |
| Wrong file type or directory supplied | Metadata check rejects non-regular files | CLI regression test; metadata/open TOCTOU remains |
| Very large file causes memory exhaustion | Fixed 64 KiB buffer | Streaming API; other process and library overhead is not capped |
| Malicious path injects terminal controls | Human output escapes control characters; JSON uses a serializer | Unit test; path display is lossy for non-Unicode paths |
| Digest algorithm confusion | Closed set of supported algorithm strings; SHA-256 default | Unsupported values are rejected; signature algorithm/version fields are checked before verification |
| Signature or signed metadata tampering | Strict versioned Seal record and SSHSIG namespace; signed message binds object version, file digest, and size | Unit and integration tests; format has not had independent review |
| Public-key substitution | Verification requires an explicit key and compares it with the SSHSIG key | Wrong-key integration test; users still need an independently authenticated key fingerprint |
| Private-key overwrite | `create_new` for private and public key output | Integration test; parent-directory ACL on Windows is inherited and not inspected |
| Private-key theft | Unix private file created as mode `0600`; key content never printed | Windows relies on the destination directory ACL; no passphrase protection is implemented |
| Digest is substituted | Not mitigated by an unsigned hash | Obtain expected digest over an independent trusted channel |
| Dependency compromise | Locked dependency resolution and CI checks | No independent audit or reproducible-build proof yet |

Seal cannot establish software safety, publisher identity, freshness, or protection from a compromised machine or source of expected digest.

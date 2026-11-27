# Threat model

## Scope

This document covers the implemented file-hashing feature only. Signing, manifests, release trust, and directory traversal are planned and have no current security guarantees.

## Assets and boundaries

- File bytes are read from a user-selected filesystem path.
- The local process and Rust hashing libraries are trusted for this operation.
- The expected digest and its delivery channel are outside Seal's control.

## Threats and controls

| Threat | Control | Verification and remaining limit |
|---|---|---|
| File content is changed while hashing | Digest is computed over bytes returned by the reader | Known vectors and read-error tests; concurrent writes may produce a digest of a changing byte stream |
| Wrong file type or directory supplied | Metadata check rejects non-regular files | CLI regression test; metadata/open TOCTOU remains |
| Very large file causes memory exhaustion | Fixed 64 KiB buffer | Streaming API; other process and library overhead is not capped |
| Malicious path injects terminal controls | Human output escapes control characters; JSON uses a serializer | Unit test; path display is lossy for non-Unicode paths |
| Digest algorithm confusion | Closed set of CLI enum values; SHA-256 default | Unsupported values are rejected; this command does not verify signed algorithm identifiers |
| Digest is substituted | Not mitigated by an unsigned hash | Obtain expected digest over an independent trusted channel |
| Dependency compromise | Locked dependency resolution and CI checks | No independent audit or reproducible-build proof yet |

Seal cannot establish software safety, publisher identity, freshness, or protection from a compromised machine or source of expected digest.

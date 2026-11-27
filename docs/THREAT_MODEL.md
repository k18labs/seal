# Threat model

## Scope

This document covers file hashing, detached file signatures, encrypted private-key storage, and directory manifests. Release trust remains dependent on an independently authenticated public key.

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
| Private-key overwrite | `create_new` for private and public key output | Integration test; directory replacement races remain an OS/filesystem concern |
| Private-key theft from disk | Argon2id plus XChaCha20-Poly1305; Unix mode `0600`; protected Windows DACL set before bytes are written | Wrong-passphrase/tamper tests; weak passphrases, compromised account/admin, backups, and memory inspection remain risks |
| Manifest path escapes root or follows links | Capability-scoped directory access and explicit no-follow opens; reject non-regular objects and non-portable paths | Junction/symlink and traversal tests; hard links are ordinary regular files and do not prove inode provenance |
| Manifest tree changes during verification | File size and modification metadata are checked before and after streaming; directory metadata checked during traversal | A race can still occur between checks or after reading; verification is not an atomic snapshot |
| Manifest resource exhaustion | Bound manifest bytes, file count, path length/depth, total declared bytes, and traversed file/directory entries; stream directory iteration | Limits are unit tested; OS resource limits are not imposed |
| Digest is substituted | Not mitigated by an unsigned hash | Obtain expected digest over an independent trusted channel |
| Dependency compromise | Locked dependency resolution and CI checks | No independent audit or reproducible-build proof yet |

Seal cannot establish software safety, publisher identity, freshness, or protection from a compromised machine or source of expected digest. No independent format or implementation audit has been completed.

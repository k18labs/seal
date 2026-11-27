# Seal v1 design

## Intent

Complete the roadmap through v1 so Seal can hash files, protect and use signing keys, create deterministic directory manifests, verify exact directory contents, and provide independently verifiable cross-platform release artifacts. Verification remains offline and requires an explicitly trusted public key.

## Goals

- Ship deterministic SHA-256 manifests over a portable set of regular files.
- Reject unsafe paths, links, special filesystem objects, malformed data, resource-limit violations, missing files, and unexpected files.
- Sign manifest bytes with a distinct SSHSIG namespace and require an explicitly selected key.
- Encrypt generated private keys with an established authenticated format and apply owner-only permissions on Unix and Windows.
- Add bounded fuzzing, regression coverage, dependency review, race analysis, and repeat-build checks.
- Build release binaries for Linux, Windows, and macOS on x86-64 and ARM64; publish checksums, SBOM, and GitHub build provenance without putting a signing secret in CI.
- Measure file hashing, manifest generation, startup, binary size, and peak memory under documented, repeatable conditions.

## Non-goals

- Following symlinks or including special files.
- Signing keys in CI, automatic installation, telemetry, network-dependent verification, trust-on-first-use, a key server, or product-specific runtime requirements.
- Claiming that CI provenance replaces independent distribution of the trusted release key or that the software has received an independent professional security audit.
- Implementing an atomic filesystem snapshot. Inputs must remain quiescent during manifest creation and verification.

## Approaches considered

1. **Extend the existing single crate (selected).** Keep hashing, manifest policy, signatures, CLI, and output in the current crate with focused modules. This preserves the established architecture and keeps release use simple.
2. **Create a workspace with separate filesystem and crypto crates.** This could isolate APIs, but the project has one binary and no independent crate consumers yet; it would add coordination and release overhead without reducing the trusted computing base.
3. **Use an existing general-purpose manifest format.** This would improve interoperability only if its path and signing rules fit Seal's strict portable tree verification. Seal will use a small, versioned JSON format and sign its exact canonical bytes; no arbitrary JSON canonicalization is assumed.

## Manifest and filesystem design

- JSON schema version 1 has fixed field order: top-level `version`, `algorithm`, `files`; entry fields `path`, `size`, `digest`.
- The algorithm is `sha256`; each digest is 64 lowercase hex characters.
- Paths are relative UTF-8 ASCII strings using `/`, sorted by UTF-8 byte order. Allowed path bytes are `[A-Za-z0-9._/-]`. Reject empty components, `.`/`..`, leading/trailing separators, Windows reserved device names, trailing dots, case-insensitive duplicates, and every non-ASCII or unrepresentable filename. This deliberately favors portable unambiguous release trees over including every local filename.
- Canonical bytes are compact JSON with no insignificant whitespace and exactly one final LF. The parser validates the schema, ordering, limits, and equality to canonical re-serialization. This rejects duplicate keys, alternate encodings, unknown fields, and ambiguous representations. Signatures cover the exact canonical byte sequence.
- Hard ceilings: 16 MiB manifest, 100,000 files, 1,024 bytes per path, 64 path components, and 1 TiB total file bytes. Manifest and file bytes are streamed or bounded; entries and paths are counted before they exceed the limits.
- Traverse through capability-scoped directory handles, refuse symlinks/reparse points and non-regular files, and hash from opened handles. No path supplied by a manifest is joined to an ambient root path. Exact verification compares the discovered file set against the manifest set.
- Directories themselves are not entries: empty directories carry no integrity data. File creation or mutation during a scan can produce a mixed-time view; the command reports operational changes when detectable and documents that scans require a quiescent tree.
- The manifest output and detached signature must be outside the scanned root. Empty trees are valid. Hard-linked files are hashed at each named path.

## Signature and key design

- Reuse OpenSSH SSHSIG and Ed25519 with namespace `seal-manifest-v1`; keep the current `seal-file-v1` namespace and its signed message unchanged.
- The outer Seal signature record identifies `object file` or `object manifest`; strict parsing rejects unknown object types.
- Private key contents are wrapped in a strict Seal v1 envelope using Argon2id (64 MiB, 3 passes, 1 lane) and XChaCha20-Poly1305. The fixed KDF parameters, random salt, 24-byte nonce, and version header are authenticated; no attacker-controlled KDF work factor is accepted. A passphrase is prompted without echo; a bounded passphrase-file option supports automation. No plaintext-key mode is added. Public keys remain OpenSSH `ssh-ed25519`.
- Unix private key files use mode `0600`. Windows private key creation uses a safe API wrapper to establish and verify a protected DACL for the owner, SYSTEM, and Administrators before encrypted key bytes are written. The file is opened without sharing during setup; failure to set or verify the DACL fails closed.

## Release and evidence design

- Keep least-privilege, immutable-SHA Actions. Build artifacts on supported native/cross targets, generate SHA-256 checksums and CycloneDX SBOM, and attach GitHub build provenance attestations. No private signing keys enter Actions.
- Bootstrap trust docs instruct users to verify the GitHub provenance identity/repository and artifact digest with GitHub's verifier, and to obtain the Seal release public key/fingerprint from an independent channel before using Seal signatures. Release artifacts are not self-authenticating merely because a checksum or public key is beside them.
- Scheduled bounded fuzzing covers manifest, signature, public-key, and path parsing. Preserve any discovered regression as a fixture/test.
- Apply deterministic linker flags where target formats contain timestamps or random identifiers; repeat release builds in clean directories and compare bytes on a fixed runner/toolchain. Treat cross-host differences or unavailable target infrastructure as explicit release limitations, not proof of reproducibility.
- Benchmarks record host, OS, toolchain, compiler flags, dependency lock, data generation, commands, repetitions, median, and peak RSS. No performance target may weaken verification.

## Constraints

- Preserve Rust, Apache-2.0, one-crate structure, pinned stable toolchain, `#![forbid(unsafe_code)]` in first-party Rust, no custom cryptography, and an explicit trusted public key.
- Keep JSON and human command results stable and errors fail closed.
- Do not publish a production release automatically. Prepare and verify a release candidate; publishing final v1 remains a deliberate maintainer action.

## Builder calls

- ASCII-only manifest paths are the portable v1 policy; non-ASCII paths fail with an actionable error.
- Output files must be outside the scanned root; outputs never receive implicit exclusion rules.
- Resource ceilings are fixed protocol/implementation limits for v1 to keep parsing and traversal bounded.
- GitHub provenance is the initial independent bootstrap mechanism; Seal signatures remain an additional artifact-authentication layer.
- An independent professional format review is not claimed unless a qualified reviewer actually completes one.
- A custom key-file envelope is used instead of the age library because the reviewed age implementation warns that its scrypt stanza's AEAD is not robust; explicit fixed Argon2id and XChaCha20-Poly1305 parameters avoid that caveat at the cost of owning a small strict envelope parser and format review.

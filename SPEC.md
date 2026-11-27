# Seal specification (initial implementation)

## Scope

Seal is an offline file-integrity CLI and reusable Rust library. Version 0.1.0 implements only regular-file hashing using SHA-256 and optional BLAKE3. It has no signing, key storage, trust policy, manifest, directory, network, or release-verification functionality.

## Current behavior

- `seal hash PATH [--algorithm sha256|blake3] [--json]` hashes a regular file with a 65,536-byte buffer.
- SHA-256 is the default. Unknown algorithm values are rejected by the CLI parser.
- `seal version` prints the package version.
- Human output is `<lowercase-hex-digest><two spaces><escaped path>`.
- JSON output is one UTF-8 JSON object with `algorithm`, `digest`, and `path` string fields. `path` uses the platform's lossy display conversion; the digest is computed from file bytes, not the path.
- Directories and other non-regular files are rejected. An I/O or type error produces no digest on stdout.
- Process exit status is 0 for success/help/version, 5 for filesystem or output failures, 6 for invalid command-line usage, and 7 for unsupported algorithms or unavailable optional algorithm support.

This specification describes the current implementation only. Future formats must have explicit versions and reject unsupported algorithms.

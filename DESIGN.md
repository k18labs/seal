# Design

Seal separates reusable hashing (`src/hash.rs`) and signature/key handling (`src/signature.rs`) from argument parsing and display (`src/main.rs`). `hash_file_with_size` checks a regular file and hashes/counts it through a fixed 64 KiB buffer. `hash_reader` is available to library users and streams any `Read` implementation. File signatures use strict metadata plus an SSHSIG envelope as specified in `docs/SIGNATURE_FORMAT.md`.

SHA-256 is mandatory. BLAKE3 is an optional Cargo feature enabled by default. First-party Rust code forbids unsafe code. No global mutable state or background process is used.

The implementation checks path metadata and then opens it, followed by an opened-handle type check. A concurrent replacement can still race between the path check and open; this is a known TOCTOU limitation. There is no directory traversal yet. Unix private keys are created with mode `0600`; Windows uses the inherited ACL of the destination directory and that ACL is not inspected or replaced.

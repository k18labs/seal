# Design

Seal separates its reusable hashing API (`src/hash.rs`) from argument parsing and display (`src/main.rs`). `hash_file` checks that the input is a regular file, then hashes through a fixed 64 KiB buffer. `hash_reader` is available to library users and streams any `Read` implementation.

SHA-256 is mandatory. BLAKE3 is an optional Cargo feature enabled by default. First-party Rust code forbids unsafe code. No global mutable state or background process is used.

The implementation currently makes a metadata check and then opens the path. A concurrent path replacement can change the object between those operations; this is a known TOCTOU limitation. This limitation is acceptable for the initial hash command, which makes no directory-verification security claim.

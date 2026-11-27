# Design

Seal keeps reusable hashing (`src/hash.rs`), manifest validation (`src/manifest.rs`), capability-based tree traversal (`src/tree.rs`), signature/key operations (`src/signature.rs`), and CLI output (`src/main.rs`) separate. Hashing streams with a 64 KiB buffer. File and manifest signatures use distinct SSHSIG namespaces and bind SHA-256 digests, lengths, and object type/version through fixed binary envelopes.

Private keys are encrypted with the fixed Argon2id/XChaCha20-Poly1305 container described in `docs/KEY_MANAGEMENT.md`. Unix files use mode `0600`; Windows applies and verifies a protected ACL before writing ciphertext. First-party Rust code forbids unsafe code; the Windows permissions crate encapsulates platform APIs.

Manifest traversal uses `cap-std`/`cap-fs-ext` directory capabilities and no-follow opens. It rejects symlinks/reparse points and special objects, constrains filenames to portable ASCII, enforces resource limits, and checks metadata around reads. This is not an atomic snapshot: concurrent mutation can still occur between checks. Manifest outputs must be outside the traversed root.

The project is offline by default and has no telemetry, service dependency, or background process. Release builds are manually dispatched and produce candidate artifacts with checksums and GitHub provenance; they do not create a GitHub Release or publish a production v1 tag.
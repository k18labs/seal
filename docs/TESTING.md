# Testing

Run `cargo test --locked`, `cargo fmt --all -- --check`, and `cargo clippy --all-targets --all-features --locked -- -D warnings`. Unit tests include SHA-256/BLAKE3 vectors, canonical manifests, parser limits, path rules, signature envelope encoding, and terminal escaping. Integration tests cover empty/large file hashing, JSON, encrypted key generation and signing, wrong passphrases, ciphertext tampering, wrong trusted keys, canonical manifest creation/signing, missing/modified/unexpected files, output path checks, and symlink/junction rejection. Unix asserts private-key mode `0600`; Windows inspects the protected DACL.

CI is configured for Linux, macOS, and Windows on x86-64 and ARM64. The remote jobs must pass before claiming all six platforms are verified. Scheduled fuzzing is configured; systematic concurrent-mutation stress tests and release candidate execution remain pre-v1 work.

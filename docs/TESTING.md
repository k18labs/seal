# Testing

The repository includes unit tests for standard SHA-256 and BLAKE3 vectors, terminal escaping, envelope encoding, and strict signature parsing. Integration tests cover empty and large-file hashing, JSON output, directory rejection, key generation, signature round-trip, modified artifacts, wrong keys, and no-overwrite behavior. Run `cargo test --locked`. Cross-platform CI covers Linux, Windows, and macOS. Fuzzing and race-condition testing are not yet configured.

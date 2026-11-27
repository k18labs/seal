# Cryptography

The current CLI offers SHA-256 and, when the default `blake3` feature is enabled, BLAKE3 through their Rust ecosystem implementations. Seal contains no handwritten cryptographic primitive. SHA-256 is the default for compatibility. BLAKE3 is a non-default algorithm choice at the command line and is not a signature algorithm.

Both digests cover the exact byte stream read from the file. Output is lowercase hexadecimal. This version defines no signed object or domain-separation construction because it does not sign anything. MD5 and SHA-1 are unsupported.

Dependency versions are resolved in `Cargo.lock`; feature and transitive dependency details can be inspected with `cargo tree --locked`. A full independent security, maintenance-history, unsafe-code, and size review remains future work.

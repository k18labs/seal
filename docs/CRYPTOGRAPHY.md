# Cryptography

The current CLI offers SHA-256 and, when the default `blake3` feature is enabled, BLAKE3 through their Rust ecosystem implementations. Seal contains no handwritten cryptographic primitive. SHA-256 is the default for compatibility. BLAKE3 is a non-default algorithm choice at the command line and is not a signature algorithm.

Both file digests cover the exact byte stream read from the file. Output is lowercase hexadecimal. Ed25519 signatures use the OpenSSH SSHSIG format, with namespace `seal-file-v1`; the signed message is a fixed Seal envelope binding object type/version, SHA-256, byte length, and the 32-byte file digest. This separates file signatures from other SSHSIG use. It uses pure Ed25519 over the small envelope through the established `ssh-key` implementation; it is not Ed25519ph. MD5 and SHA-1 are unsupported.

Dependency versions are resolved in `Cargo.lock`; feature and transitive dependency details can be inspected with `cargo tree --locked`. `ssh-key` 0.6.7 is pinned and compiled with default features disabled, enabling only `std`, `ed25519`, and `getrandom`; it brings in `ed25519-dalek` and `zeroize` transitively. Its license is Apache-2.0 OR MIT. The encrypted OpenSSH-key feature is not enabled. A full independent security, maintenance-history, unsafe-code, and size review remains future work.

Format and algorithm references: [OpenSSH PROTOCOL.sshsig](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig) and [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html).

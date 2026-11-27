# Cryptography

The current CLI offers SHA-256 and, when the default `blake3` feature is enabled, BLAKE3 through their Rust ecosystem implementations. Seal contains no handwritten cryptographic primitive. SHA-256 is the default for compatibility. BLAKE3 is a non-default algorithm choice at the command line and is not a signature algorithm.

Both file digests cover the exact byte stream read from the file. Output is lowercase hexadecimal. Ed25519 signatures use OpenSSH SSHSIG with namespace `seal-file-v1` for files and `seal-manifest-v1` for manifests. The signed message is a fixed Seal envelope binding object type/version, SHA-256, byte length, and the 32-byte digest. This separates file signatures from manifests and other SSHSIG use. It uses pure Ed25519 over the small envelope through the established `ssh-key` implementation; it is not Ed25519ph. MD5 and SHA-1 are unsupported.

Private-key files use the fixed `SEAL-PRIVATE-KEY 1` container. Argon2id v19 uses 64 MiB, 3 iterations, 1 lane, and a 32-byte output; XChaCha20-Poly1305 encrypts OpenSSH private-key text with a random 16-byte salt and 24-byte nonce. The complete magic/salt/nonce header is authenticated as associated data. There is no plaintext fallback. The maintainer reports that qualified external review of this format found no blocking findings; the report is not included in this repository. KDF changes require a new format version.

Dependency versions are resolved in `Cargo.lock`; feature and transitive dependency details can be inspected with `cargo tree --locked`. `ssh-key` 0.6.7 is pinned and compiled with default features disabled, enabling only `std`, `ed25519`, and `getrandom`; it brings in `ed25519-dalek` and `zeroize` transitively. Its license is Apache-2.0 OR MIT. OpenSSH encrypted-key support is disabled; Seal's container handles private-key encryption. The qualified external format review is reported complete; a broader independent dependency and maintenance-history audit is not claimed.

Format and algorithm references: [OpenSSH PROTOCOL.sshsig](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig) and [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html).

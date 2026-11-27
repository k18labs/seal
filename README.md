# Seal

Seal is an offline-first Rust command-line tool for checking file integrity. It provides streaming SHA-256 and optional BLAKE3 hashing, plus Ed25519 file signatures in a versioned Seal record containing an OpenSSH SSHSIG signature. Verification requires an explicitly selected public key. Directory manifests are not implemented yet.

## Build

Install Rust 1.96.0 or use rustup with the included `rust-toolchain.toml`:

```sh
cargo build --release --locked
```

## Use

```sh
seal hash artifact.tar.gz
seal hash artifact.tar.gz --algorithm sha256
seal hash artifact.tar.gz --algorithm blake3
seal hash artifact.tar.gz --json
seal keygen --out ./keys/release
seal key fingerprint --public-key ./keys/release.pub
seal sign artifact.tar.gz --key ./keys/release --output artifact.tar.gz.seal
seal verify artifact.tar.gz --signature artifact.tar.gz.seal --public-key ./keys/release.pub
seal version
```

Hashing uses a fixed 64 KiB buffer. JSON output is one object on stdout; errors go to stderr. SHA-256 is the default. An unsigned digest proves integrity only when its expected value comes from a trusted channel. A valid signature does not establish trust unless the supplied public key was obtained through a trusted channel. See [key management](docs/KEY_MANAGEMENT.md) and [signature format](docs/SIGNATURE_FORMAT.md).

To build without optional BLAKE3 support, use `cargo build --no-default-features --locked`.

## Project status

The foundation and file hashing are in place; file signing and verification are implemented, with remaining key-storage hardening documented in [ROADMAP.md](ROADMAP.md). Directory manifest verification, fuzzing, and an independent security audit have not been completed. This tool is not an antivirus and does not determine whether a file is safe to run.

## License

Apache-2.0. See [LICENSE](LICENSE).
